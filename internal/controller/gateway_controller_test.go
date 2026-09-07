//go:build envtest

// Copyright (c) 2026 Damien Daly. All rights reserved.

package controller

import (
	"strings"
	"testing"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const testGatewayImage = "ghcr.io/maitredede/mailout-operator:test"

func newGatewayReconciler(c client.Client) *GatewayReconciler {
	return &GatewayReconciler{
		Client:            c,
		Scheme:            scheme,
		APIReader:         c,
		OperatorNamespace: operatorNamespace,
		GatewayImage:      testGatewayImage,
	}
}

func reconcileGateway(t *testing.T, r *GatewayReconciler, gw *v1alpha1.MailoutGateway) {
	t.Helper()
	if _, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(gw),
	}); err != nil {
		t.Fatalf("reconcile gateway: %v", err)
	}
}

func refreshGateway(t *testing.T, c client.Client, gw *v1alpha1.MailoutGateway) *v1alpha1.MailoutGateway {
	t.Helper()
	var fresh v1alpha1.MailoutGateway
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), &fresh); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	return &fresh
}

// renderedConfig parses the configuration the operator published.
func renderedConfig(t *testing.T, c client.Client, gatewayName string) *gateway.Config {
	t.Helper()
	secret := getSecret(t, c, operatorNamespace, render.ConfigSecretName(gatewayName))
	raw := secret.Data[render.ConfigFileName]
	if len(raw) == 0 {
		t.Fatalf("configuration Secret has no %s key", render.ConfigFileName)
	}
	cfg := &gateway.Config{}
	if err := yaml.UnmarshalStrict(raw, cfg); err != nil {
		t.Fatalf("published configuration does not parse:\n%s\n%v", raw, err)
	}
	return cfg
}

func TestGatewayCreatesItsWorkload(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "workload", func(g *v1alpha1.MailoutGateway) {
		g.Spec.Listeners = v1alpha1.ListenersSpec{
			Submission: &v1alpha1.ListenerSpec{},
			SMTPS:      &v1alpha1.ListenerSpec{},
		}
	})

	reconcileGateway(t, newGatewayReconciler(c), gw)

	var deployment appsv1.Deployment
	key := client.ObjectKey{Namespace: operatorNamespace, Name: "workload"}
	if err := c.Get(t.Context(), key, &deployment); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	if container.Image != testGatewayImage {
		t.Fatalf("image = %q", container.Image)
	}
	if len(container.Ports) != 2 {
		t.Fatalf("ports = %+v", container.Ports)
	}

	var svc corev1.Service
	if err := c.Get(t.Context(), key, &svc); err != nil {
		t.Fatalf("get service: %v", err)
	}
	if len(svc.Spec.Ports) != 2 {
		t.Fatalf("service ports = %+v", svc.Spec.Ports)
	}

	// The published configuration must be one the dataplane accepts.
	cfg := renderedConfig(t, c, "workload")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("published configuration is invalid: %v", err)
	}
	if len(cfg.Listeners) != 2 {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}

	fresh := refreshGateway(t, c, gw)
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatalf("not accepted: %+v", fresh.Status.Conditions)
	}
	// No pods run under envtest, so Ready is expected to be false with a
	// reason that says exactly that.
	condition := meta.FindStatusCondition(fresh.Status.Conditions, v1alpha1.ConditionReady)
	if condition == nil || condition.Reason != v1alpha1.ReasonDeploymentNotReady {
		t.Fatalf("ready condition = %+v", condition)
	}
	if len(fresh.Status.Listeners) != 2 || fresh.Status.ServiceName != "workload" {
		t.Fatalf("status = %+v", fresh.Status)
	}
}

// The whole point of the two controllers together: an account's hash must end
// up in the gateway's published configuration.
func TestGatewayPublishesAccountHashes(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "withaccounts")
	ns := newNamespace(t, c, "tenant")
	account := newAccount(t, c, ns, "app", gw.Name)

	reconcileAccount(t, newAccountReconciler(c), account)
	reconcileGateway(t, newGatewayReconciler(c), gw)

	cfg := renderedConfig(t, c, "withaccounts")
	if len(cfg.Accounts) != 1 {
		t.Fatalf("accounts = %+v", cfg.Accounts)
	}
	if cfg.Accounts[0].Username != ns+".app" {
		t.Fatalf("username = %q", cfg.Accounts[0].Username)
	}
	// The published hash must be the one in the account's own Secret, and the
	// cleartext must never appear in the gateway's configuration.
	secret := getSecret(t, c, ns, "app-smtp")
	if cfg.Accounts[0].PasswordHash != string(secret.Data[render.PasswordHashKey]) {
		t.Fatal("the published hash is not the account's own")
	}
	raw := getSecret(t, c, operatorNamespace, render.ConfigSecretName("withaccounts")).Data[render.ConfigFileName]
	if password := string(secret.Data[corev1.BasicAuthPasswordKey]); strings.Contains(string(raw), password) {
		t.Fatal("the cleartext password leaked into the gateway configuration")
	}
	if got := refreshGateway(t, c, gw).Status.AcceptedAccounts; got != 1 {
		t.Fatalf("acceptedAccounts = %d", got)
	}
}

// An account with no Secret yet must not break the rendering; it simply is not
// published until its own controller has provisioned it.
func TestGatewaySkipsUnprovisionedAccounts(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "pending")
	ns := newNamespace(t, c, "tenant")
	newAccount(t, c, ns, "notyet", gw.Name)

	reconcileGateway(t, newGatewayReconciler(c), gw)

	cfg := renderedConfig(t, c, "pending")
	if len(cfg.Accounts) != 0 {
		t.Fatalf("an unprovisioned account was published: %+v", cfg.Accounts)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("configuration with no account should still be valid: %v", err)
	}
}

// The upstream password comes from a Secret the user owns, and must reach the
// rendered configuration.
func TestGatewayResolvesUpstreamCredentials(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	upstream := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "upstream-creds", Namespace: operatorNamespace},
		Type:       corev1.SecretTypeBasicAuth,
		StringData: map[string]string{"username": "relay", "password": "hunter2"},
	}
	if err := c.Create(t.Context(), upstream); err != nil {
		t.Fatalf("create upstream secret: %v", err)
	}
	gw := newGateway(t, c, "upstreamauth", func(g *v1alpha1.MailoutGateway) {
		g.Spec.Upstream.AuthSecretRef = &v1alpha1.LocalObjectReference{Name: "upstream-creds"}
	})

	reconcileGateway(t, newGatewayReconciler(c), gw)

	cfg := renderedConfig(t, c, "upstreamauth")
	if cfg.Upstream.Username != "relay" || cfg.Upstream.Password != "hunter2" {
		t.Fatalf("upstream credentials = %+v", cfg.Upstream)
	}
}

// A missing upstream Secret is reported, not silently ignored: the relay would
// otherwise authenticate with nothing and fail at delivery time.
func TestGatewayReportsMissingUpstreamSecret(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "missingsecret", func(g *v1alpha1.MailoutGateway) {
		g.Spec.Upstream.AuthSecretRef = &v1alpha1.LocalObjectReference{Name: "absent"}
	})

	reconcileGateway(t, newGatewayReconciler(c), gw)

	condition := meta.FindStatusCondition(refreshGateway(t, c, gw).Status.Conditions, v1alpha1.ConditionAccepted)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != v1alpha1.ReasonSecretMissing {
		t.Fatalf("accepted condition = %+v", condition)
	}
}

// Serving a gateway from a tenant namespace would put its upstream credentials
// within that tenant's reach.
func TestGatewayOutsideOperatorNamespaceIsRefused(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	ns := newNamespace(t, c, "tenant")
	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "rogue", Namespace: ns},
		Spec: v1alpha1.MailoutGatewaySpec{
			TLS:      v1alpha1.GatewayTLSSpec{CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "tls"}}},
			Upstream: v1alpha1.UpstreamSpec{Host: "smtp.upstream.test", Port: 587},
		},
	}
	if err := c.Create(t.Context(), gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	reconcileGateway(t, newGatewayReconciler(c), gw)

	condition := meta.FindStatusCondition(refreshGateway(t, c, gw).Status.Conditions, v1alpha1.ConditionAccepted)
	if condition == nil || condition.Reason != v1alpha1.ReasonInvalidSpec {
		t.Fatalf("accepted condition = %+v", condition)
	}
	var deployment appsv1.Deployment
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), &deployment); err == nil {
		t.Fatal("a gateway outside the operator namespace got a Deployment")
	}
}

// Asking for an issuer without cert-manager installed must say so, not fail
// forever on a kind that does not exist.
func TestGatewayIssuerRefWithoutCertManager(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "noissuer", func(g *v1alpha1.MailoutGateway) {
		g.Spec.TLS = v1alpha1.GatewayTLSSpec{
			IssuerRef: &v1alpha1.IssuerReference{Name: "letsencrypt"},
			DNSNames:  []string{"mail.example.test"},
		}
	})

	r := newGatewayReconciler(c)
	r.CertManagerAvailable = false
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	if err == nil {
		t.Fatal("expected an error explaining cert-manager is missing")
	}
	if got := err.Error(); !strings.Contains(got, "cert-manager") {
		t.Fatalf("error should mention cert-manager, got %q", got)
	}
}

// With cert-manager present, the operator owns the Certificate.
func TestGatewayCreatesCertificate(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	// envtest has no cert-manager CRDs, so the object cannot actually be
	// created; the rendering is what this test pins down.
	gw := newGateway(t, c, "withissuer", func(g *v1alpha1.MailoutGateway) {
		g.Spec.TLS = v1alpha1.GatewayTLSSpec{
			IssuerRef: &v1alpha1.IssuerReference{Name: "letsencrypt", Kind: "ClusterIssuer"},
			DNSNames:  []string{"mail.example.test"},
		}
	})
	cert := render.Certificate(gw)
	if cert == nil || cert.Spec.SecretName != "withissuer-tls" {
		t.Fatalf("certificate = %+v", cert)
	}
	// And the rendered configuration must read the certificate from where that
	// Secret gets mounted.
	cfg, err := render.GatewayConfig(render.Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if got := cfg.TLS.Certificates[0].CertFile; got != "/etc/mailout/tls/withissuer-tls/tls.crt" {
		t.Fatalf("certFile = %q", got)
	}
}

// Adding an account must not change the pod template: a rollout would drop live
// SMTP connections, and the gateway reloads accounts from disk anyway.
func TestGatewayDoesNotRestartPodsWhenAccountsChange(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "norestart")
	r := newGatewayReconciler(c)
	reconcileGateway(t, r, gw)

	var before appsv1.Deployment
	key := client.ObjectKey{Namespace: operatorNamespace, Name: "norestart"}
	if err := c.Get(t.Context(), key, &before); err != nil {
		t.Fatalf("get deployment: %v", err)
	}

	ns := newNamespace(t, c, "tenant")
	account := newAccount(t, c, ns, "late", gw.Name)
	reconcileAccount(t, newAccountReconciler(c), account)
	reconcileGateway(t, r, refreshGateway(t, c, gw))

	var after appsv1.Deployment
	if err := c.Get(t.Context(), key, &after); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	beforeHash := before.Spec.Template.Annotations[render.RestartHashAnnotation]
	afterHash := after.Spec.Template.Annotations[render.RestartHashAnnotation]
	if beforeHash != afterHash {
		t.Fatalf("restart hash changed from %q to %q on an account change", beforeHash, afterHash)
	}
	if before.Generation != after.Generation {
		t.Fatalf("the Deployment was updated (generation %d -> %d)", before.Generation, after.Generation)
	}

	// But the configuration Secret must have been updated with the new account.
	cfg := renderedConfig(t, c, "norestart")
	if len(cfg.Accounts) != 1 {
		t.Fatalf("the new account was not published: %+v", cfg.Accounts)
	}
}
