//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package cluster runs the operator against a real Kubernetes cluster — a
// throwaway k3s in a container — and checks the thing that no other test can:
// that the gateway the operator deploys actually starts, accepts a login, and
// relays a message.
//
// The operator itself runs in-process against the cluster's kubeconfig, so a
// failure points at a line of Go rather than at a pod that will not start.
package cluster

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	"github.com/maitredede/mailout-operator/internal/controller"
	"github.com/maitredede/mailout-operator/internal/render"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// k3sImage pins the cluster version. Kept in step with the envtest version, so
// the two suites test against the same API.
const k3sImage = "rancher/k3s:v1.34.9-k3s1"

// Fixed node ports, so the test can reach the cluster from outside: the
// container only publishes ports declared at creation time.
const (
	gatewayNodePort = 31587
	mailpitNodePort = 31825
)

const (
	operatorNamespace = "mailout-system"
	tenantNamespace   = "billing"
	// gatewayCertName is the name the client asks for, and the name the
	// throwaway certificate carries.
	gatewayCertName = "mailout.cluster.test"
)

// defaultTestImage is the image the gateway pods run. Build it first:
//
//	make docker-build IMG=mailout-operator:test
const defaultTestImage = "mailout-operator:test"

// testImage is the image under test.
func testImage() string {
	if image := os.Getenv("MAILOUT_TEST_IMAGE"); image != "" {
		return image
	}
	return defaultTestImage
}

// cluster is a running k3s with the CRDs installed and the operator
// reconciling.
type cluster struct {
	Client client.Client
	// Clientset reads pod logs, which the typed client cannot do and which is
	// the only way to see why a gateway pod refuses to start.
	Clientset *kubernetes.Clientset
	// GatewaySMTPAddr and MailpitAPIURL are reachable from the test process.
	GatewaySMTPAddr string
	MailpitAPIURL   string
}

// scheme knows every type the test manipulates.
func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	utilruntime.Must(certmanagerv1.AddToScheme(s))
	return s
}

// startCluster brings up k3s with the CRDs and a Mailpit standing in for the
// upstream server, then starts the reconcilers.
func startCluster(t *testing.T) *cluster {
	t.Helper()
	// Containers are torn down from Cleanup, which runs after t.Context() has
	// already been cancelled.
	ctx := context.Background()

	// controller-runtime complains loudly if no logger is set before its first
	// client is built.
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(io.Discard)))

	manifests := t.TempDir()
	crdPath := filepath.Join(manifests, "mailout-crds.yaml")
	writeCRDs(t, crdPath)
	supportPath := filepath.Join(manifests, "mailout-support.yaml")
	if err := os.WriteFile(supportPath, []byte(supportManifest), 0o644); err != nil {
		t.Fatalf("write support manifest: %v", err)
	}

	container, err := k3s.Run(ctx, k3sImage,
		k3s.WithManifest(crdPath),
		k3s.WithManifest(supportPath),
		// The kubelet sees the host's filesystem, so a developer machine with a
		// nearly-full disk trips the default DiskPressure threshold and the node
		// taints itself NoSchedule. This cluster lives for one test, so the
		// eviction thresholds are of no use here.
		testcontainers.WithCmdArgs(
			"--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%,memory.available<50Mi",
			"--kubelet-arg=eviction-soft=",
		),
		testcontainers.WithExposedPorts(
			fmt.Sprintf("%d/tcp", gatewayNodePort),
			fmt.Sprintf("%d/tcp", mailpitNodePort),
		),
	)
	if err != nil {
		t.Fatalf("start k3s: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	// The gateway pods run the image under test, which only exists locally.
	if err := container.LoadImages(ctx, testImage()); err != nil {
		t.Fatalf("load image %s into the cluster: %v\n"+
			"Build it first: make docker-build IMG=%s", testImage(), err, testImage())
	}

	kubeconfig, err := container.GetKubeConfig(ctx)
	if err != nil {
		t.Fatalf("get kubeconfig: %v", err)
	}
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		t.Fatalf("parse kubeconfig: %v", err)
	}
	scheme := newScheme(t)
	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	smtpPort, err := container.MappedPort(ctx, fmt.Sprintf("%d/tcp", gatewayNodePort))
	if err != nil {
		t.Fatalf("gateway port: %v", err)
	}
	apiPort, err := container.MappedPort(ctx, fmt.Sprintf("%d/tcp", mailpitNodePort))
	if err != nil {
		t.Fatalf("mailpit port: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatalf("create clientset: %v", err)
	}

	cl := &cluster{
		Client:          c,
		Clientset:       clientset,
		GatewaySMTPAddr: fmt.Sprintf("%s:%s", host, smtpPort.Port()),
		MailpitAPIURL:   fmt.Sprintf("http://%s:%s", host, apiPort.Port()),
	}

	waitForCRDs(t, c)
	startReconcilers(t, restConfig, scheme)
	return cl
}

// writeCRDs renders the CRDs k3s applies at startup.
func writeCRDs(t *testing.T, path string) {
	t.Helper()
	crdDir := filepath.Join("..", "..", "config", "crd", "bases")
	entries, err := os.ReadDir(crdDir)
	if err != nil {
		t.Fatalf("read %s: %v", crdDir, err)
	}
	var combined []byte
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(crdDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		combined = append(combined, []byte("---\n")...)
		combined = append(combined, raw...)
	}
	if err := os.WriteFile(path, combined, 0o644); err != nil {
		t.Fatalf("write CRDs: %v", err)
	}
}

// supportManifest is what the cluster needs besides the CRDs: the operator's
// namespace, the tenant's, and a Mailpit standing in for the upstream SMTP
// server, exposed so the test can read what arrived.
const supportManifest = `
apiVersion: v1
kind: Namespace
metadata:
  name: mailout-system
---
apiVersion: v1
kind: Namespace
metadata:
  name: billing
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mailpit
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels: {app: mailpit}
  template:
    metadata:
      labels: {app: mailpit}
    spec:
      containers:
        - name: mailpit
          image: axllent/mailpit:v1.31.1
          env:
            - {name: MP_SMTP_AUTH_ACCEPT_ANY, value: "true"}
            - {name: MP_SMTP_AUTH_ALLOW_INSECURE, value: "true"}
          ports:
            - {containerPort: 1025}
            - {containerPort: 8025}
---
apiVersion: v1
kind: Service
metadata:
  name: mailpit
  namespace: default
spec:
  type: NodePort
  selector: {app: mailpit}
  ports:
    - {name: smtp, port: 1025, targetPort: 1025}
    - {name: http, port: 8025, targetPort: 8025, nodePort: 31825}
`

// waitForCRDs blocks until the API serves the mailout types; k3s applies the
// manifests asynchronously after the node is ready.
func waitForCRDs(t *testing.T, c client.Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		var list v1alpha1.MailoutGatewayList
		if err := c.List(t.Context(), &list); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("the CRDs were not served within two minutes")
}

// startReconcilers runs the operator in-process against the cluster.
func startReconcilers(t *testing.T, restConfig *rest.Config, scheme *runtime.Scheme) {
	t.Helper()
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	if err := (&controller.GatewayReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		APIReader:         mgr.GetAPIReader(),
		OperatorNamespace: operatorNamespace,
		GatewayImage:      testImage(),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("set up gateway controller: %v", err)
	}
	if err := (&controller.AccountReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: operatorNamespace,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("set up account controller: %v", err)
	}

	// The manager is stopped through its own context, which must outlive
	// t.Context() so that Cleanup can wait for it.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the manager did not stop")
		}
	})
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("the manager's cache did not sync")
	}
}

// waitForDeployment blocks until the gateway has an available replica, which
// only happens once its readiness probe connects to the SMTP port — so this is
// also proof that the rendered configuration was accepted.
func (cl *cluster) waitForDeployment(t *testing.T, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	key := client.ObjectKey{Namespace: operatorNamespace, Name: name}
	for time.Now().Before(deadline) {
		var deployment appsv1.Deployment
		if err := cl.Client.Get(t.Context(), key, &deployment); err == nil {
			if deployment.Status.AvailableReplicas > 0 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	cl.describeGatewayPods(t)
	t.Fatalf("the gateway Deployment had no available replica within %s", timeout)
}

// describeGatewayPods reports what the pods are doing and what they logged, so
// a failure says why rather than just that it timed out.
func (cl *cluster) describeGatewayPods(t *testing.T) {
	t.Helper()
	var pods corev1.PodList
	if err := cl.Client.List(t.Context(), &pods, client.InNamespace(operatorNamespace)); err != nil {
		t.Logf("list pods: %v", err)
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		t.Logf("pod %s: phase=%s", pod.Name, pod.Status.Phase)
		for _, status := range pod.Status.ContainerStatuses {
			t.Logf("  container %s: ready=%v restarts=%d state=%+v",
				status.Name, status.Ready, status.RestartCount, status.State)
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Status != corev1.ConditionTrue {
				t.Logf("  condition %s=%s %s", condition.Type, condition.Status, condition.Message)
			}
		}
		t.Logf("  logs:\n%s", cl.podLogs(t, pod.Name, false))
		if logs := cl.podLogs(t, pod.Name, true); logs != "" {
			t.Logf("  logs (previous attempt):\n%s", logs)
		}
	}
}

// podLogs returns a container's log, which is where a startup failure explains
// itself.
func (cl *cluster) podLogs(t *testing.T, podName string, previous bool) string {
	t.Helper()
	stream, err := cl.Clientset.CoreV1().Pods(operatorNamespace).
		GetLogs(podName, &corev1.PodLogOptions{Container: "gateway", Previous: previous}).
		Stream(t.Context())
	if err != nil {
		return fmt.Sprintf("(could not read logs: %v)", err)
	}
	defer stream.Close()
	body, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Sprintf("(could not read logs: %v)", err)
	}
	return string(body)
}

// nodePortService exposes the gateway's pods on a fixed node port. The operator
// deliberately does not manage node ports, so the test owns this Service.
func nodePortService(gatewayName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gatewayName + "-nodeport",
			Namespace: operatorNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: render.SelectorLabels(gatewayName),
			Ports: []corev1.ServicePort{{
				Name:       "submission",
				Port:       587,
				TargetPort: intstr.FromInt32(587),
				NodePort:   gatewayNodePort,
			}},
		},
	}
}
