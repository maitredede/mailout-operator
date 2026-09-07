//go:build envtest

// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
)

const operatorNamespace = "mailout-system"

// The webhooks are exercised through a real API server, so what these tests
// check is what a kubectl apply would actually get.
var (
	testEnv    *envtest.Environment
	testClient client.Client
	scheme     *runtime.Scheme
)

func TestMain(m *testing.M) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(discardWriter{})))

	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		Scheme:                scheme,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "..", "config", "webhook", "manifests.yaml")},
		},
	}
	restConfig, err := testEnv.Start()
	if err != nil {
		panic("start envtest: " + err.Error())
	}

	// The manager serves the webhooks the API server was just told about.
	install := testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(restConfig, manager.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: webhookserver.NewServer(webhookserver.Options{
			Host:    install.LocalServingHost,
			Port:    install.LocalServingPort,
			CertDir: install.LocalServingCertDir,
		}),
	})
	if err != nil {
		panic("create manager: " + err.Error())
	}
	if err := SetupGatewayWebhookWithManager(mgr, operatorNamespace, true); err != nil {
		panic("set up gateway webhook: " + err.Error())
	}
	if err := SetupAccountWebhookWithManager(mgr, operatorNamespace); err != nil {
		panic("set up account webhook: " + err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("run manager: " + err.Error())
		}
	}()
	if err := waitForWebhookServer(install.LocalServingHost, install.LocalServingPort); err != nil {
		panic(err.Error())
	}

	testClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		panic("create client: " + err.Error())
	}
	if err := testClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		panic("create operator namespace: " + err.Error())
	}

	code := m.Run()
	cancel()
	if err := testEnv.Stop(); err != nil {
		panic("stop envtest: " + err.Error())
	}
	if code != 0 {
		panic("tests failed")
	}
}

// waitForWebhookServer blocks until the webhook server accepts connections;
// without this the first test races the manager's startup.
func waitForWebhookServer(host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only handshake against a self-signed serving cert
		if err == nil {
			return conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("webhook server did not start listening on %s", addr)
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func newNamespace(t *testing.T, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	if err := testClient.Create(t.Context(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}
