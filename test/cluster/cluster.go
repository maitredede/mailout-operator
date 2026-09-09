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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
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
	metricsNodePort = 31909
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
	// GatewaySMTPAddr, MailpitAPIURL and MetricsURL are reachable from the test
	// process.
	GatewaySMTPAddr string
	MailpitAPIURL   string
	MetricsURL      string

	restConfig *rest.Config
	scheme     *runtime.Scheme
	container  *k3s.K3sContainer
}

// loadTestImage makes the locally built image available to the cluster's
// container runtime; nothing pulls it from a registry.
func (cl *cluster) loadTestImage(t *testing.T) error {
	t.Helper()
	// The load outlives t.Context() in the same way the container does.
	return cl.container.LoadImages(context.Background(), testImage())
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
// upstream server, then runs the reconcilers in-process.
//
// Use it to test behaviour. To test the deployment itself — the operator running
// as a pod, its webhook, cert-manager — use startBareCluster instead: two
// operators reconciling one cluster would fight.
func startCluster(t *testing.T) *cluster {
	t.Helper()
	cl := startBareCluster(t, true)
	if err := cl.loadTestImage(t); err != nil {
		t.Fatalf("load image %s into the cluster: %v\n"+
			"Build it first: make docker-build IMG=%s", testImage(), err, testImage())
	}
	waitForCRDs(t, cl.Client)
	startReconcilers(t, cl.restConfig, cl.scheme)
	return cl
}

// startBareCluster brings up k3s and Mailpit, with the CRDs installed only if
// asked. Nothing reconciles: the caller decides what runs.
func startBareCluster(t *testing.T, installCRDs bool) *cluster {
	t.Helper()
	// Containers are torn down from Cleanup, which runs after t.Context() has
	// already been cancelled.
	ctx := context.Background()

	// controller-runtime complains loudly if no logger is set before its first
	// client is built.
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(io.Discard)))

	manifests := t.TempDir()
	supportPath := filepath.Join(manifests, "mailout-support.yaml")
	if err := os.WriteFile(supportPath, []byte(supportManifest), 0o644); err != nil {
		t.Fatalf("write support manifest: %v", err)
	}
	startupManifests := []testcontainers.ContainerCustomizer{k3s.WithManifest(supportPath)}
	if installCRDs {
		crdPath := filepath.Join(manifests, "mailout-crds.yaml")
		writeCRDs(t, crdPath)
		startupManifests = append(startupManifests, k3s.WithManifest(crdPath))
	}

	options := []testcontainers.ContainerCustomizer{
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
			fmt.Sprintf("%d/tcp", metricsNodePort),
		),
	}
	options = append(options, startupManifests...)

	container, err := k3s.Run(ctx, k3sImage, options...)
	if err != nil {
		t.Fatalf("start k3s: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

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
	metricsPort, err := container.MappedPort(ctx, fmt.Sprintf("%d/tcp", metricsNodePort))
	if err != nil {
		t.Fatalf("metrics port: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatalf("create clientset: %v", err)
	}

	return &cluster{
		Client:          c,
		Clientset:       clientset,
		GatewaySMTPAddr: fmt.Sprintf("%s:%s", host, smtpPort.Port()),
		MailpitAPIURL:   fmt.Sprintf("http://%s:%s", host, apiPort.Port()),
		MetricsURL:      fmt.Sprintf("http://%s:%s%s", host, metricsPort.Port(), render.MetricsPath),
		restConfig:      restConfig,
		scheme:          scheme,
		container:       container,
	}
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
		// Several tests in this package each start their own manager in the
		// same process, and controller-runtime refuses two controllers with the
		// same name because their metrics would collide. That is a real
		// safeguard in a real operator, and pure noise here.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
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

// waitForPublishedHash blocks until the gateway's rendered configuration
// carries the hash currently in the account's Secret. It separates "the
// operator has not republished" from "the pod has not reloaded yet", which look
// identical from the client side.
func (cl *cluster) waitForPublishedHash(t *testing.T, gatewayName, accountNamespace, accountSecret string,
	timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var wanted, published string
	for time.Now().Before(deadline) {
		var secret corev1.Secret
		if err := cl.Client.Get(t.Context(), client.ObjectKey{
			Namespace: accountNamespace, Name: accountSecret,
		}, &secret); err != nil {
			time.Sleep(time.Second)
			continue
		}
		wanted = string(secret.Data[render.PasswordHashKey])

		var config corev1.Secret
		if err := cl.Client.Get(t.Context(), client.ObjectKey{
			Namespace: operatorNamespace, Name: render.ConfigSecretName(gatewayName),
		}, &config); err == nil {
			published = string(config.Data[render.ConfigFileName])
			if wanted != "" && strings.Contains(published, wanted) {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the operator never published the account's current hash within %s\n"+
		"wanted hash: %s\npublished configuration:\n%s", timeout, wanted, published)
}

// newNamespace creates a uniquely named namespace, so that tenants in a test
// cannot collide with each other or with another test's leftovers.
func (cl *cluster) newNamespace(t *testing.T, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	if err := cl.Client.Create(t.Context(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}

// mailpitMessage is one message as the upstream reports it.
type mailpitMessage struct {
	ID      string
	Subject string
}

// errUnexpectedLookup marks a DNS lookup a test did not expect, so a stray
// query cannot pass for a successful verification.
var errUnexpectedLookup = errors.New("unexpected DKIM record lookup")

// mailpitMessages lists what the upstream received.
func (cl *cluster) mailpitMessages(t *testing.T) []mailpitMessage {
	t.Helper()
	resp, err := http.Get(cl.MailpitAPIURL + "/api/v1/messages")
	if err != nil {
		t.Fatalf("list upstream messages: %v", err)
	}
	defer resp.Body.Close()
	var payload struct {
		Messages []mailpitMessage
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode upstream messages: %v", err)
	}
	return payload.Messages
}

// mailpitRaw returns a received message as it arrived on the wire, which is what
// the DKIM assertions need.
func (cl *cluster) mailpitRaw(t *testing.T, id string) string {
	t.Helper()
	resp, err := http.Get(cl.MailpitAPIURL + "/api/v1/message/" + id + "/raw")
	if err != nil {
		t.Fatalf("fetch raw message: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read raw message: %v", err)
	}
	return string(body)
}

// waitForMailpitMessage returns the raw message with the given subject.
func waitForMailpitMessage(t *testing.T, apiURL, subject string, timeout time.Duration) string {
	t.Helper()
	cl := &cluster{MailpitAPIURL: apiURL}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, message := range cl.mailpitMessages(t) {
			if message.Subject == subject {
				return cl.mailpitRaw(t, message.ID)
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no message with subject %q reached the upstream within %s", subject, timeout)
	return ""
}

// scrapeMetrics fetches the dataplane's Prometheus endpoint, retrying while
// kube-proxy programs the node port for the newly ready pod.
func scrapeMetrics(t *testing.T, url, token string, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	var lastErr error
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read metrics: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %s", resp.Status)
			time.Sleep(time.Second)
			continue
		}
		return string(body)
	}
	t.Fatalf("the metrics endpoint at %s never answered within %s: %v", url, timeout, lastErr)
	return ""
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
			}, {
				// Published only so the test can scrape the pod from outside
				// the cluster. In a real deployment the metrics live on their
				// own ClusterIP Service, never on the SMTP one.
				Name:       render.MetricsPortName,
				Port:       render.MetricsPort,
				TargetPort: intstr.FromString(render.MetricsPortName),
				NodePort:   metricsNodePort,
			}},
		},
	}
}

// scrapeStatus reports what the metrics endpoint answers, without requiring it
// to succeed — used to check that an unauthenticated scrape is refused.
func scrapeStatus(t *testing.T, url, token string, timeout time.Duration) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// The node port may not be programmed yet.
			time.Sleep(time.Second)
			continue
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	t.Fatalf("the metrics endpoint at %s never answered within %s", url, timeout)
	return 0
}
