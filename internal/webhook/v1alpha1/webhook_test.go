//go:build envtest

// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// validGateway is the minimum a gateway needs to be admitted.
func validGateway(name string, mutate ...func(*v1alpha1.MailoutGateway)) *v1alpha1.MailoutGateway {
	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname: "mail.example.test",
			TLS: v1alpha1.GatewayTLSSpec{
				CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "mail-tls"}},
			},
			Upstream: v1alpha1.UpstreamSpec{
				Host: "smtp.upstream.test", Port: 587, TLS: v1alpha1.TLSModeStartTLS,
			},
		},
	}
	for _, m := range mutate {
		m(gw)
	}
	return gw
}

// createGateway returns the admission error, if any.
func createGateway(t *testing.T, gw *v1alpha1.MailoutGateway) error {
	t.Helper()
	return testClient.Create(t.Context(), gw)
}

func TestGatewayAdmitted(t *testing.T) {
	if err := createGateway(t, validGateway("admitted")); err != nil {
		t.Fatalf("a valid gateway was refused: %v", err)
	}
}

func TestGatewayRefusedWithoutTLS(t *testing.T) {
	err := createGateway(t, validGateway("notls", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.TLS = v1alpha1.GatewayTLSSpec{}
	}))
	if err == nil {
		t.Fatal("a gateway with no TLS configuration was admitted")
	}
	if !strings.Contains(err.Error(), "certificateRefs or issuerRef") {
		t.Fatalf("unexpected message: %v", err)
	}
}

// Giving both would leave it ambiguous which certificate is actually served.
func TestGatewayRefusedWithBothCertificateSources(t *testing.T) {
	err := createGateway(t, validGateway("bothtls", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.TLS.IssuerRef = &v1alpha1.IssuerReference{Name: "letsencrypt"}
	}))
	if err == nil {
		t.Fatal("a gateway with both certificateRefs and issuerRef was admitted")
	}
}

func TestGatewayRefusedOutsideOperatorNamespace(t *testing.T) {
	ns := newNamespace(t, "tenant")
	err := createGateway(t, validGateway("rogue", func(gw *v1alpha1.MailoutGateway) {
		gw.Namespace = ns
	}))
	if err == nil {
		t.Fatal("a gateway outside the operator namespace was admitted")
	}
	if !strings.Contains(err.Error(), "operator namespace") {
		t.Fatalf("unexpected message: %v", err)
	}
}

// A malformed milter address would only fail later, at delivery time.
func TestGatewayRefusedWithBadMilterAddress(t *testing.T) {
	err := createGateway(t, validGateway("badmilter", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.Milters = []v1alpha1.MilterSpec{{Name: "clamav", Address: "http://nope"}}
	}))
	if err == nil {
		t.Fatal("a gateway with an unusable milter address was admitted")
	}
	if !strings.Contains(err.Error(), "tcp://") {
		t.Fatalf("the message should say what is accepted: %v", err)
	}
}

func TestGatewayRefusedWithDuplicateDKIMDomain(t *testing.T) {
	err := createGateway(t, validGateway("dupdkim", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.DKIM = []v1alpha1.DKIMKeySpec{
			{Domain: "example.com", Selector: "a", PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "k1"}},
			{Domain: "Example.com", Selector: "b", PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "k2"}},
		}
	}))
	if err == nil {
		t.Fatal("two keys for the same domain were admitted")
	}
}

func TestGatewayRefusedWithUnknownDefaultCertificate(t *testing.T) {
	err := createGateway(t, validGateway("baddefault", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.TLS.DefaultCertificate = "not-in-the-list"
	}))
	if err == nil {
		t.Fatal("an unknown defaultCertificate was admitted")
	}
}

func TestGatewayRefusedWithCollidingListenerPorts(t *testing.T) {
	err := createGateway(t, validGateway("collide", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.Listeners = v1alpha1.ListenersSpec{
			Submission: &v1alpha1.ListenerSpec{Port: 2525},
			SMTPS:      &v1alpha1.ListenerSpec{Port: 2525},
		}
	}))
	if err == nil {
		t.Fatal("two listeners on the same port were admitted")
	}
}

func TestGatewaySelectorRequiredWithSelectorMode(t *testing.T) {
	err := createGateway(t, validGateway("noselector", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.AllowedAccounts = v1alpha1.AllowedAccountsSpec{
			Namespaces: v1alpha1.NamespacesFromSelector,
		}
	}))
	if err == nil {
		t.Fatal("Selector mode without a selector was admitted")
	}
}

// An account with no gateway cannot be provisioned, so it is refused at apply
// time rather than sitting in a status nobody watches.
func TestAccountRefusedWithoutGateway(t *testing.T) {
	ns := newNamespace(t, "tenant")
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "no-such-gateway"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "orphan-smtp"},
		},
	}
	err := testClient.Create(t.Context(), account)
	if err == nil {
		t.Fatal("an account referencing no gateway was admitted")
	}
	if !strings.Contains(err.Error(), "no such MailoutGateway") {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestAccountAdmittedWithGateway(t *testing.T) {
	if err := createGateway(t, validGateway("hostgw")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "hostgw"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "app-smtp"},
		},
	}
	if err := testClient.Create(t.Context(), account); err != nil {
		t.Fatalf("a valid account was refused: %v", err)
	}
}

// Two accounts claiming one username on the same gateway is refused up front.
func TestAccountRefusedOnUsernameConflict(t *testing.T) {
	if err := createGateway(t, validGateway("conflictgw")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	first := newNamespace(t, "first")
	second := newNamespace(t, "second")

	makeAccount := func(namespace, name string) *v1alpha1.MailoutAccount {
		return &v1alpha1.MailoutAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: v1alpha1.MailoutAccountSpec{
				GatewayRef: v1alpha1.GatewayReference{Name: "conflictgw"},
				SecretRef:  v1alpha1.LocalObjectReference{Name: name + "-smtp"},
				Username:   "shared@example.test",
			},
		}
	}
	if err := testClient.Create(t.Context(), makeAccount(first, "a")); err != nil {
		t.Fatalf("create first account: %v", err)
	}
	err := testClient.Create(t.Context(), makeAccount(second, "b"))
	if err == nil {
		t.Fatal("a duplicate username was admitted")
	}
	if !strings.Contains(err.Error(), "already used by") {
		t.Fatalf("unexpected message: %v", err)
	}
}

// A gateway restricted to its own namespace refuses a foreign account at
// admission, not just in status.
func TestAccountRefusedWhenNamespaceNotAllowed(t *testing.T) {
	if err := createGateway(t, validGateway("samens", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.AllowedAccounts = v1alpha1.AllowedAccountsSpec{Namespaces: v1alpha1.NamespacesFromSame}
	})); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "outsider", Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "samens"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "outsider-smtp"},
		},
	}
	if err := testClient.Create(t.Context(), account); err == nil {
		t.Fatal("a foreign account was admitted")
	}
}

// Taking over an existing Secret would destroy its contents on the first
// reconciliation.
func TestAccountRefusedWhenSecretExistsAndIsNotOurs(t *testing.T) {
	if err := createGateway(t, validGateway("secretgw")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "precious", Namespace: ns},
		StringData: map[string]string{"something": "important"},
	}
	if err := testClient.Create(t.Context(), existing); err != nil {
		t.Fatalf("create existing secret: %v", err)
	}
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "grabby", Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "secretgw"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "precious"},
		},
	}
	err := testClient.Create(t.Context(), account)
	if err == nil {
		t.Fatal("an account pointing at somebody else's Secret was admitted")
	}
	if !strings.Contains(err.Error(), "would overwrite") {
		t.Fatalf("unexpected message: %v", err)
	}
}
