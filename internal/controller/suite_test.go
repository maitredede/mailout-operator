//go:build envtest

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// testEnv is the shared control plane. Starting one per test would cost several
// seconds each; the reconcilers are stateless, so one is enough.
var (
	testEnv    *envtest.Environment
	restConfig *rest.Config
	scheme     *runtime.Scheme
)

const operatorNamespace = "mailout-system"

func TestMain(m *testing.M) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(testWriter{})))

	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		Scheme:                scheme,
	}
	var err error
	restConfig, err = testEnv.Start()
	if err != nil {
		panic("start envtest: " + err.Error())
	}
	code := m.Run()
	if err := testEnv.Stop(); err != nil {
		panic("stop envtest: " + err.Error())
	}
	if code != 0 {
		panic("tests failed")
	}
}

// testWriter silences controller-runtime's logging; a failing test says what it
// needs itself.
type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

// newTestClient returns a direct client — no cache, so a write is immediately
// visible and the tests need no polling for their own writes.
func newTestClient(t *testing.T) client.Client {
	t.Helper()
	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c
}

// newNamespace creates a uniquely named namespace, so tests do not interfere.
func newNamespace(t *testing.T, c client.Client, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	// envtest never garbage-collects namespaces, so nothing is deleted here;
	// each test simply gets a fresh one.
	if err := c.Create(t.Context(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}

// ensureOperatorNamespace creates the operator namespace once per control plane.
func ensureOperatorNamespace(t *testing.T, c client.Client) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}}
	if err := c.Create(t.Context(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create operator namespace: %v", err)
	}
}

// eventually retries until the condition holds or the deadline passes. envtest
// has no controllers running in the background, but a reconciler's own writes
// still need a moment to be readable.
func eventually(t *testing.T, timeout time.Duration, what string, condition func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	var lastErr error
	for {
		if lastErr = condition(ctx); lastErr == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", what, lastErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
