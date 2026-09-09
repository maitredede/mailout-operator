//go:build envtest

// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"testing"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
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
			// A gateway that grants nothing lets no account send anything, so a
			// fixture has to grant something or every account test would fail
			// on the grant rather than on what it is checking. No selector, so
			// it applies to every namespace the gateway accepts.
			AllowedSenders: []v1alpha1.SenderGrantSpec{{
				Senders: []string{
					"*@example.test", "*@mail.example.test", "*@other.test", "*@tenant.test",
				},
			}},
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

// The metrics port is not configurable, so a listener claiming it would have the
// two bind the same address: one loses with EADDRINUSE and takes the process
// down, and the pod crash-loops for a reason nothing in the spec hints at.
func TestGatewayRefusedWhenAListenerClaimsTheMetricsPort(t *testing.T) {
	for name, listeners := range map[string]v1alpha1.ListenersSpec{
		"submission": {Submission: &v1alpha1.ListenerSpec{Port: render.MetricsPort}},
		"smtps":      {SMTPS: &v1alpha1.ListenerSpec{Port: render.MetricsPort}},
	} {
		t.Run(name, func(t *testing.T) {
			err := createGateway(t, validGateway("metrics-port-"+name, func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.Listeners = listeners
			}))
			if err == nil {
				t.Fatalf("a %s listener on the metrics port was admitted", name)
			}
		})
	}
}

func TestGatewayRateLimitValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*v1alpha1.MailoutGateway)
		admit   bool
		message string
	}{
		{
			name: "valid standalone store",
			mutate: func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.RateLimit = &v1alpha1.RateLimitSpec{
					Store:             v1alpha1.RateLimitStoreSpec{Addresses: []string{"valkey:6379"}},
					MessagesPerMinute: ptr.To(int32(60)),
				}
			},
			admit: true,
		},
		{
			name: "valid sentinel store",
			mutate: func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.RateLimit = &v1alpha1.RateLimitSpec{
					Store: v1alpha1.RateLimitStoreSpec{
						Addresses:  []string{"s1:26379", "s2:26379", "s3:26379"},
						MasterName: "mailout",
					},
					RecipientsPerMinute: ptr.To(int32(300)),
				}
			},
			admit: true,
		},
		{
			name: "address without a port",
			mutate: func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.RateLimit = &v1alpha1.RateLimitSpec{
					Store:             v1alpha1.RateLimitStoreSpec{Addresses: []string{"valkey"}},
					MessagesPerMinute: ptr.To(int32(60)),
				}
			},
			message: "host:port",
		},
		{
			name: "no address at all",
			mutate: func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.RateLimit = &v1alpha1.RateLimitSpec{
					Store:             v1alpha1.RateLimitStoreSpec{},
					MessagesPerMinute: ptr.To(int32(60)),
				}
			},
			// Caught by the CRD's own MinItems before the webhook sees it.
			message: "",
		},
		{
			// Sentinel credentials without Sentinel: a configuration that would
			// silently do nothing.
			name: "sentinel credentials without masterName",
			mutate: func(gw *v1alpha1.MailoutGateway) {
				gw.Spec.RateLimit = &v1alpha1.RateLimitSpec{
					Store: v1alpha1.RateLimitStoreSpec{
						Addresses:             []string{"valkey:6379"},
						SentinelAuthSecretRef: &v1alpha1.LocalObjectReference{Name: "sentinel-auth"},
					},
					MessagesPerMinute: ptr.To(int32(60)),
				}
			},
			message: "masterName",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "rl" + strings.ReplaceAll(strings.ToLower(tc.name), " ", "")
			err := createGateway(t, validGateway(name, tc.mutate))
			if tc.admit {
				if err != nil {
					t.Fatalf("a valid rate limit was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("an invalid rate limit was admitted")
			}
			if tc.message != "" && !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("the message should mention %q: %v", tc.message, err)
			}
		})
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
	// A username now has to be namespace-qualified, so a collision can only
	// happen inside one namespace — which is the tenant's own business, but
	// still has to be refused: two accounts sharing a username would make
	// authentication ambiguous.
	ns := newNamespace(t, "first")

	makeAccount := func(name string) *v1alpha1.MailoutAccount {
		return &v1alpha1.MailoutAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1alpha1.MailoutAccountSpec{
				GatewayRef: v1alpha1.GatewayReference{Name: "conflictgw"},
				SecretRef:  v1alpha1.LocalObjectReference{Name: name + "-smtp"},
				Username:   ns + ".shared",
			},
		}
	}
	if err := testClient.Create(t.Context(), makeAccount("a")); err != nil {
		t.Fatalf("create first account: %v", err)
	}
	err := testClient.Create(t.Context(), makeAccount("b"))
	if err == nil {
		t.Fatal("a duplicate username was admitted")
	}
	if !strings.Contains(err.Error(), "already taken") {
		t.Fatalf("unexpected message: %v", err)
	}
	// The message must not name the holder: it reaches whoever ran kubectl
	// apply, and naming the other account is how a tenant maps the others.
	if strings.Contains(err.Error(), "/a") {
		t.Errorf("the refusal names the account holding the username: %v", err)
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
// The username reaches the Received header of every message the account sends,
// so a control character in it would let the account write headers of its own.
// The CRD pattern is what refuses it, before any controller sees the object.
// A headerKeys set without From is not a weaker signature, it is a 451 on every
// message of that domain — the signing library refuses outright.
func TestGatewayRefusedWhenHeaderKeysOmitFrom(t *testing.T) {
	err := createGateway(t, validGateway("nofrom", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.DKIM = []v1alpha1.DKIMKeySpec{{
			Domain:              "example.test",
			Selector:            "sel",
			PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-example"},
			HeaderKeys:          []string{"Subject", "Date"},
		}}
	}))
	if err == nil {
		t.Fatal("a DKIM key signing neither From nor anything containing it was admitted")
	}

	// Declaring it explicitly is fine.
	if err := createGateway(t, validGateway("withfrom", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.DKIM = []v1alpha1.DKIMKeySpec{{
			Domain:              "example.test",
			Selector:            "sel",
			PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-example"},
			HeaderKeys:          []string{"from", "Subject"},
		}}
	})); err != nil {
		t.Fatalf("a set including From should be admitted: %v", err)
	}
}

func TestAccountUsernameRejectsControlCharacters(t *testing.T) {
	if err := createGateway(t, validGateway("uname")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")

	for name, username := range map[string]string{
		"crlf":      "app1\r\nX-Injected: pwned\r\nFrom: ceo@victim.test\r\n\r\nINJECTED",
		"line feed": "app1\nX-Injected: pwned",
		"space":     "app 1",
		"colon":     "app:1",
		"too long":  strings.Repeat("a", 129),
	} {
		t.Run(name, func(t *testing.T) {
			err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
				ObjectMeta: metav1.ObjectMeta{Name: "acct-" + strings.Map(alphanumeric, name), Namespace: ns},
				Spec: v1alpha1.MailoutAccountSpec{
					GatewayRef: v1alpha1.GatewayReference{Name: "uname"},
					SecretRef:  v1alpha1.LocalObjectReference{Name: "s"},
					Username:   username,
				},
			})
			if err == nil {
				t.Fatalf("username %q was admitted", username)
			}
		})
	}
}

// The CRD cannot bound the username the operator computes when the field is
// left empty, so the webhook checks the effective value. Without this, a
// namespace and an object name that are each legal produce a username that is
// silently dropped from the served configuration — an account that reports
// nothing wrong and never works.
// Every allowedSenders entry is rendered into the gateway's shared
// configuration Secret, which the API server caps at 1 MiB. Unbounded, one
// account made that Secret unwritable — and since the previous one stays in
// service, the relay kept running while no change ever applied again, so the
// admin lost the ability to disable anyone.
// A username outside its own namespace's space is how one tenant takes
// another's SMTP identity: name it first and the legitimate account is refused,
// or race it and the winner is decided by list order — alphabetically, so a
// namespace called aaa- beats one called zzz-.
// The finding this closes: an account used to declare its own sending rights,
// so on a gateway holding keys for several tenants nothing stopped one from
// writing another's domain into its own allowedSenders and having it signed.
// The grant is the gateway owner's, and a namespaceSelector is what ties a
// domain to the tenant it belongs to.
func TestAccountCannotClaimAnotherTenantsGrantedDomain(t *testing.T) {
	victim := newNamespace(t, "victim")
	attacker := newNamespace(t, "attacker")

	// Label the namespaces, which is what the grants select on.
	for ns, tenant := range map[string]string{victim: "victim", attacker: "attacker"} {
		var namespace corev1.Namespace
		if err := testClient.Get(t.Context(), types.NamespacedName{Name: ns}, &namespace); err != nil {
			t.Fatalf("get namespace %s: %v", ns, err)
		}
		if namespace.Labels == nil {
			namespace.Labels = map[string]string{}
		}
		namespace.Labels["tenant"] = tenant
		if err := testClient.Update(t.Context(), &namespace); err != nil {
			t.Fatalf("label namespace %s: %v", ns, err)
		}
	}

	// One gateway, both tenants' domains, each granted to its own namespace.
	if err := createGateway(t, validGateway("shared", func(gw *v1alpha1.MailoutGateway) {
		gw.Spec.AllowedSenders = []v1alpha1.SenderGrantSpec{
			{
				Senders: []string{"*@victim.test"},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tenant": "victim"},
				},
			},
			{
				Senders: []string{"*@attacker.test"},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"tenant": "attacker"},
				},
			},
		}
	})); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	makeAccount := func(ns, name string, senders []string) *v1alpha1.MailoutAccount {
		return &v1alpha1.MailoutAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1alpha1.MailoutAccountSpec{
				GatewayRef:     v1alpha1.GatewayReference{Name: "shared"},
				SecretRef:      v1alpha1.LocalObjectReference{Name: name + "-smtp"},
				AllowedSenders: senders,
			},
		}
	}

	// The attack: the attacker's namespace claiming the victim's domain.
	err := testClient.Create(t.Context(), makeAccount(attacker, "evil", []string{"*@victim.test"}))
	if err == nil {
		t.Fatal("an account claimed a domain granted to another namespace")
	}
	if !strings.Contains(err.Error(), "not granted to namespace") {
		t.Errorf("unexpected refusal: %v", err)
	}

	// An exact address inside the other tenant's domain is refused too: the
	// wildcard grant is what would have covered it, and it is not theirs.
	if err := testClient.Create(t.Context(),
		makeAccount(attacker, "evil2", []string{"ceo@victim.test"})); err == nil {
		t.Error("an exact address in another namespace's granted domain was admitted")
	}

	// Its own domain, on the other hand, is its own.
	if err := testClient.Create(t.Context(),
		makeAccount(attacker, "legit", []string{"*@attacker.test"})); err != nil {
		t.Errorf("an account was refused its own granted domain: %v", err)
	}

	// And so is the victim's, for the victim.
	if err := testClient.Create(t.Context(),
		makeAccount(victim, "app", []string{"noreply@victim.test"})); err != nil {
		t.Errorf("the victim was refused a subset of its own grant: %v", err)
	}
}

// An account that declares nothing gets its namespace's whole grant: the
// gateway's owner has already decided, and making every tenant restate it would
// only add a place for the two to disagree.
func TestAccountWithNoDeclarationIsAdmitted(t *testing.T) {
	if err := createGateway(t, validGateway("inherit")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")
	if err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "inherit"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "app-smtp"},
		},
	}); err != nil {
		t.Errorf("an account declaring no sender was refused: %v", err)
	}
}

func TestAccountUsernameMustBeNamespaceQualified(t *testing.T) {
	if err := createGateway(t, validGateway("qualified")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	victim := newNamespace(t, "zzz-victim")
	attacker := newNamespace(t, "aaa-attacker")

	// The attacker naming the victim's identity, before the victim exists.
	err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "evil", Namespace: attacker},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "qualified"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "evil-smtp"},
			Username:   victim + ".app",
		},
	})
	if err == nil {
		t.Fatalf("an account in %s claimed the username %s.app", attacker, victim)
	}

	// Its own namespace, on the other hand, is its own business.
	if err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "legit", Namespace: attacker},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "qualified"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "legit-smtp"},
			Username:   attacker + ".whatever-it-likes",
		},
	}); err != nil {
		t.Errorf("an account naming an identity inside its own namespace was refused: %v", err)
	}

	// And the default needs no help.
	if err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: victim},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "qualified"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "app-smtp"},
		},
	}); err != nil {
		t.Errorf("the default username was refused: %v", err)
	}
}

func TestAccountAllowedSendersAreBounded(t *testing.T) {
	if err := createGateway(t, validGateway("bounded")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")

	makeAccount := func(name string, senders []string) *v1alpha1.MailoutAccount {
		return &v1alpha1.MailoutAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1alpha1.MailoutAccountSpec{
				GatewayRef:     v1alpha1.GatewayReference{Name: "bounded"},
				SecretRef:      v1alpha1.LocalObjectReference{Name: name + "-smtp"},
				AllowedSenders: senders,
			},
		}
	}

	// One entry of 700 KB: valid in form (one @, no wildcard), so only a length
	// bound stops it.
	huge := strings.Repeat("a", 700*1024) + "@attacker.test"
	if err := testClient.Create(t.Context(), makeAccount("one-huge", []string{huge})); err == nil {
		t.Error("a 700 KB sender entry was admitted")
	}

	// Or many entries, each individually plausible.
	many := make([]string, 0, 64)
	for i := range 64 {
		many = append(many, fmt.Sprintf("app%d@attacker.test", i))
	}
	if err := testClient.Create(t.Context(), makeAccount("too-many", many)); err == nil {
		t.Error("64 sender entries were admitted past the 32 item bound")
	}

	// And what a real account declares still works.
	if err := testClient.Create(t.Context(), makeAccount("reasonable",
		[]string{"*@example.test", "app@other.test"})); err != nil {
		t.Errorf("a reasonable account was refused: %v", err)
	}
}

func TestAccountRejectedWhenTheDefaultUsernameIsTooLong(t *testing.T) {
	if err := createGateway(t, validGateway("longdefault")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, strings.Repeat("n", 50))
	name := strings.Repeat("a", 90)

	err := testClient.Create(t.Context(), &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "longdefault"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "s"},
		},
	})
	if err == nil {
		t.Fatalf("an account whose default username is %d characters was admitted", len(ns)+1+len(name))
	}
	if !strings.Contains(err.Error(), "spec.username") {
		t.Errorf("the error should point the tenant at spec.username: %v", err)
	}
}

// alphanumeric keeps a subtest name usable as an object name.
func alphanumeric(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return r
	default:
		return -1
	}
}

// spec.milters.disable is gone, and a residual one is pruned rather than
// honoured. A tenant used it to skip the gateway's virus scanner: the filters
// belong to whoever owns the gateway, and an account that needs different ones
// belongs on a different gateway.
func TestAccountMiltersFieldIsPruned(t *testing.T) {
	if err := createGateway(t, validGateway("prunemilters")); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	ns := newNamespace(t, "tenant")

	account := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "mailout.daly.nc/v1alpha1",
		"kind":       "MailoutAccount",
		"metadata":   map[string]any{"name": "opt-out", "namespace": ns},
		"spec": map[string]any{
			"gatewayRef": map[string]any{"name": "prunemilters"},
			"secretRef":  map[string]any{"name": "opt-out-smtp"},
			"milters":    map[string]any{"disable": []any{"clamav"}},
		},
	}}
	if err := testClient.Create(t.Context(), account); err != nil {
		t.Fatalf("create: %v", err)
	}

	var stored unstructured.Unstructured
	stored.SetGroupVersionKind(account.GroupVersionKind())
	if err := testClient.Get(t.Context(),
		types.NamespacedName{Namespace: ns, Name: "opt-out"}, &stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, found, _ := unstructured.NestedMap(stored.Object, "spec", "milters"); found {
		t.Error("spec.milters survived, so an account could still ask to skip a filter")
	}
}

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
