//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

package cluster

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestTenantsCannotSignForEachOther is the adversarial scenario: two tenants,
// two domains, both keys on the same gateway, and one tenant trying to have the
// other's domain signed.
//
// Before the sender policy existed, this worked: MAIL FROM was accepted
// verbatim and the signer picked its key from the sender's domain, so any
// account could make the gateway vouch for any domain it held a key for.
func TestTenantsCannotSignForEachOther(t *testing.T) {
	cl := startCluster(t)
	c := cl.Client

	ca, err := pki.NewCA("mailout isolation test")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	serverCert, err := ca.Issue(gatewayCertName, "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM)
	if err := c.Create(t.Context(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "isolation-tls", Namespace: operatorNamespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": serverCert.CertPEM, "tls.key": serverCert.KeyPEM},
	}); err != nil {
		t.Fatalf("create TLS secret: %v", err)
	}

	// One key per tenant domain, both held by the same gateway — which is the
	// whole point: the keys are there, and the attacker still cannot use them.
	keys := map[string]*gateway.GeneratedDKIMKey{}
	for _, domain := range []string{"attacker.test", "victim.test"} {
		key, err := gateway.GenerateDKIMKey("rsa", domain, "mail")
		if err != nil {
			t.Fatalf("GenerateDKIMKey(%s): %v", domain, err)
		}
		keys[domain] = key
		if err := c.Create(t.Context(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "dkim-" + domain, Namespace: operatorNamespace},
			Data:       map[string][]byte{"private.key": []byte(key.PrivateKeyPEM)},
		}); err != nil {
			t.Fatalf("create DKIM secret for %s: %v", domain, err)
		}
	}

	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname:  gatewayCertName,
			Listeners: v1alpha1.ListenersSpec{Submission: &v1alpha1.ListenerSpec{}},
			TLS: v1alpha1.GatewayTLSSpec{
				CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "isolation-tls"}},
			},
			Upstream: v1alpha1.UpstreamSpec{
				Host: "mailpit.default.svc.cluster.local", Port: 1025, TLS: v1alpha1.TLSModeNone,
			},
			DKIM: []v1alpha1.DKIMKeySpec{
				{Domain: "attacker.test", Selector: "mail",
					PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-attacker.test"}},
				{Domain: "victim.test", Selector: "mail",
					PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-victim.test"}},
			},
			Deployment: v1alpha1.DeploymentSpec{Replicas: ptrTo(int32(1))},
		},
	}
	if err := c.Create(t.Context(), gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	attackerNS := cl.newNamespace(t, "attacker")
	attacker := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: attackerNS},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef:     v1alpha1.GatewayReference{Name: "shared"},
			SecretRef:      v1alpha1.LocalObjectReference{Name: "app-smtp"},
			AllowedSenders: []string{"*@attacker.test"},
		},
	}
	if err := c.Create(t.Context(), attacker); err != nil {
		t.Fatalf("create attacker account: %v", err)
	}
	if err := c.Create(t.Context(), nodePortService("shared")); err != nil {
		t.Fatalf("create node port service: %v", err)
	}

	cl.waitForDeployment(t, "shared", 3*time.Minute)
	credentials := waitForAccountSecret(t, c, attackerNS, "app-smtp", 2*time.Minute)
	username := string(credentials.Data[corev1.BasicAuthUsernameKey])
	password := string(credentials.Data[corev1.BasicAuthPasswordKey])

	// Sanity check: the attacker's own domain does work, and is signed. Without
	// this the test could pass by simply being broken.
	const legitimate = "isolation legitimate"
	if err := waitForSuccessfulSubmissionAs(t, cl.GatewaySMTPAddr, caPool, username, password,
		legitimate, "app@attacker.test", "app@attacker.test", 2*time.Minute); err != nil {
		cl.describeGatewayPods(t)
		t.Fatalf("the account cannot even use its own domain: %v", err)
	}
	raw := waitForMailpitMessage(t, cl.MailpitAPIURL, legitimate, time.Minute)
	if !strings.Contains(raw, "DKIM-Signature:") {
		t.Fatalf("the account's own domain was not signed:\n%s", raw)
	}

	victimLookup := func(name string) ([]string, error) {
		if name != "mail._domainkey.victim.test" {
			return nil, errUnexpectedLookup
		}
		return []string{keys["victim.test"].DNSRecordValue}, nil
	}

	// Attempt 1: forge the envelope. Must be refused outright.
	err = submitAs(t, cl.GatewaySMTPAddr, caPool, username, password,
		"isolation envelope spoof", "ceo@victim.test", "ceo@victim.test")
	if err == nil {
		t.Fatal("the gateway accepted an envelope from another tenant's domain")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("want a permanent 550, got %v", err)
	}

	// Attempt 2: legitimate envelope, forged From header. Must be refused too —
	// the From is what the recipient sees.
	err = submitAs(t, cl.GatewaySMTPAddr, caPool, username, password,
		"isolation header spoof", "app@attacker.test", "ceo@victim.test")
	if err == nil {
		t.Fatal("the gateway accepted a forged From header")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Fatalf("want a permanent 550, got %v", err)
	}

	// Nothing signed for the victim reached anyone.
	for _, message := range cl.mailpitMessages(t) {
		raw := cl.mailpitRaw(t, message.ID)
		if !strings.Contains(raw, "victim.test") {
			continue
		}
		verifications, err := dkim.VerifyWithOptions(strings.NewReader(raw),
			&dkim.VerifyOptions{LookupTXT: victimLookup})
		if err == nil {
			for _, verification := range verifications {
				if verification.Domain == "victim.test" && verification.Err == nil {
					t.Fatalf("a message carries a valid victim.test signature:\n%s", raw)
				}
			}
		}
	}
}
