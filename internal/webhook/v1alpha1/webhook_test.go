//go:build envtest

// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func TestAccountAllowedSendersValidation(t *testing.T) {
	if err := createGateway(t, validGateway("senders")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")

	makeAccount := func(name string, senders []string) *v1alpha1.MailoutAccount {
		return &v1alpha1.MailoutAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1alpha1.MailoutAccountSpec{
				GatewayRef:     v1alpha1.GatewayReference{Name: "senders"},
				SecretRef:      v1alpha1.LocalObjectReference{Name: name + "-smtp"},
				AllowedSenders: senders,
			},
		}
	}

	if err := testClient.Create(t.Context(), makeAccount("valid",
		[]string{"app@example.test", "*@mail.example.test"})); err != nil {
		t.Fatalf("a valid allowedSenders list was refused: %v", err)
	}

	// A malformed entry is refused rather than silently ignored: dropping it
	// would narrow the policy in a way the author did not ask for, and they
	// would discover it as mail being refused.
	tests := map[string][]string{
		"no-at":           {"example.test"},
		"no-local":        {"@example.test"},
		"no-domain":       {"app@"},
		"partial-local":   {"app*@example.test"},
		"wildcard-domain": {"*@*.example.test"},
		"duplicate":       {"app@example.test", "APP@example.test"},
	}
	for name, senders := range tests {
		t.Run(name, func(t *testing.T) {
			if err := testClient.Create(t.Context(), makeAccount(name, senders)); err == nil {
				t.Fatalf("allowedSenders %v was admitted", senders)
			}
		})
	}
}

// The removed per-account DKIM field must not come back by accident. Sent as an
// unknown field, the API server prunes it — what matters is that it does not
// survive, since it used to let a tenant name any Secret of the operator's
// namespace for mounting.
func TestAccountDKIMFieldIsPruned(t *testing.T) {
	if err := createGateway(t, validGateway("prunedkim")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")

	account := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "mailout.daly.nc/v1alpha1",
		"kind":       "MailoutAccount",
		"metadata":   map[string]any{"name": "sneaky", "namespace": ns},
		"spec": map[string]any{
			"gatewayRef":     map[string]any{"name": "prunedkim"},
			"secretRef":      map[string]any{"name": "sneaky-smtp"},
			"allowedSenders": []any{"app@tenant.test"},
			"dkim": []any{map[string]any{
				"domain":              "victim.test",
				"selector":            "mail",
				"privateKeySecretRef": map[string]any{"name": "upstream-credentials"},
			}},
		},
	}}
	if err := testClient.Create(t.Context(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, found, _ := unstructured.NestedSlice(account.Object, "spec", "dkim"); found {
		t.Fatal("spec.dkim survived; a tenant could still name a Secret to mount")
	}
}
