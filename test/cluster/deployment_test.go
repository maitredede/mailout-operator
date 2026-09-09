//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// assertSingleLeader checks that leader election settled on exactly one holder.
func assertSingleLeader(t *testing.T, cl *cluster, timeout time.Duration) {
	t.Helper()
	const leaseName = "mailout-operator.mailout.daly.nc"
	deadline := time.Now().Add(timeout)
	var lease coordinationv1.Lease
	key := client.ObjectKey{Namespace: operatorNamespace, Name: leaseName}
	for time.Now().Before(deadline) {
		if err := cl.Client.Get(t.Context(), key, &lease); err == nil &&
			lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		t.Fatalf("no leader held %s within %s: %+v", leaseName, timeout, lease.Spec)
	}

	var leases coordinationv1.LeaseList
	if err := cl.Client.List(t.Context(), &leases, client.InNamespace(operatorNamespace)); err != nil {
		t.Fatalf("list leases: %v", err)
	}
	if len(leases.Items) != 1 {
		names := make([]string, 0, len(leases.Items))
		for _, l := range leases.Items {
			names = append(names, l.Name)
		}
		t.Fatalf("expected one lease in %s, got %v", operatorNamespace, names)
	}
	t.Logf("leader election settled on %s", *lease.Spec.HolderIdentity)
}

// TestDeployedOperatorWithCertManager exercises the deployment rather than the
// behaviour: the operator runs as a pod from config/default, its webhook serves
// a cert-manager certificate with the CA injected into the
// ValidatingWebhookConfiguration, and the gateway's own listener certificate is
// issued by cert-manager too.
//
// This is the only test that covers config/default and the cert-manager chain.
// It is slow — a cert-manager install and two rollouts — and that is the price
// of knowing the manifests in this repository actually work.
func TestDeployedOperatorWithCertManager(t *testing.T) {
	// No in-process reconcilers here: the operator under test runs in the
	// cluster, and two of them would fight over the same objects.
	cl := startBareCluster(t, false)
	c := cl.Client

	if err := cl.loadTestImage(t); err != nil {
		t.Fatalf("load image %s into the cluster: %v\n"+
			"Build it first: make docker-build IMG=%s", testImage(), err, testImage())
	}

	t.Log("installing cert-manager", certManagerVersion)
	applyYAML(t, c, certManagerManifest(t))
	cl.waitForDeploymentsAvailable(t, "cert-manager",
		[]string{"cert-manager", "cert-manager-webhook", "cert-manager-cainjector"}, 5*time.Minute)

	t.Log("deploying the operator from config/default")
	applyYAML(t, c, kustomizeBuild(t, "config/default"))
	cl.waitForDeploymentsAvailable(t, operatorNamespace, []string{"mailout-operator"}, 3*time.Minute)

	// High availability is not a manifest that says replicas: 2, it is two pods
	// actually running with exactly one of them reconciling. Both halves are
	// worth asserting: a required anti-affinity rule would leave the second pod
	// Pending on this single-node cluster, and a leader election that failed to
	// engage would have both of them writing to the same objects.
	cl.waitForReadyReplicas(t, operatorNamespace, "mailout-operator", 2, 3*time.Minute)
	assertSingleLeader(t, cl, 2*time.Minute)

	// The webhook must actually answer before anything is created: its
	// failurePolicy is Fail, so an unreachable webhook rejects every write. That
	// it eventually answers proves the cainjector filled in the caBundle and the
	// operator is serving TLS with the cert-manager certificate.
	waitForWebhook(t, c, 2*time.Minute)

	// An invalid gateway must be refused by that webhook, not merely reported in
	// a status field.
	invalid := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			// No certificateRefs and no issuerRef.
			Upstream: v1alpha1.UpstreamSpec{Host: "smtp.upstream.test", Port: 587},
		},
	}
	err := c.Create(t.Context(), invalid)
	if err == nil {
		t.Fatal("the deployed webhook admitted a gateway with no TLS configuration")
	}
	if !strings.Contains(err.Error(), "certificateRefs or issuerRef") {
		t.Fatalf("the rejection did not come from our webhook: %v", err)
	}

	// A self-signed issuer stands in for a real ACME one: what is being tested
	// is that the operator creates the Certificate and that the gateway serves
	// what cert-manager put in the Secret.
	applyYAML(t, c, []byte(selfSignedIssuer))

	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "secure", Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname: gatewayCertName,
			// The gateway grants the sending rights; an account can only narrow them.
			AllowedSenders: []v1alpha1.SenderGrantSpec{{Senders: []string{"*@example.test"}}},
			Listeners:      v1alpha1.ListenersSpec{Submission: &v1alpha1.ListenerSpec{}},
			TLS: v1alpha1.GatewayTLSSpec{
				IssuerRef: &v1alpha1.IssuerReference{Name: "mailout-test-ca", Kind: "Issuer"},
				DNSNames:  []string{gatewayCertName},
			},
			Upstream: v1alpha1.UpstreamSpec{
				Host: "mailpit.default.svc.cluster.local",
				Port: 1025,
				TLS:  v1alpha1.TLSModeNone,
			},
			Deployment: v1alpha1.DeploymentSpec{Replicas: ptrTo(int32(1))},
		},
	}
	if err := c.Create(t.Context(), gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	// The operator must have created the Certificate, and cert-manager must
	// have issued it.
	certificate := &unstructured.Unstructured{}
	certificate.SetGroupVersionKind(certmanagerv1.GroupVersion.WithKind("Certificate"))
	certificate.SetNamespace(operatorNamespace)
	certificate.SetName("secure")
	waitForCondition(t, c, certificate, "Ready", "True", 3*time.Minute)

	var tlsSecret corev1.Secret
	if err := c.Get(t.Context(), client.ObjectKey{
		Namespace: operatorNamespace, Name: "secure-tls",
	}, &tlsSecret); err != nil {
		t.Fatalf("the issued certificate Secret is missing: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(tlsSecret.Data["ca.crt"]) {
		t.Fatal("the issued Secret carries no usable ca.crt")
	}

	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "secure-app", Namespace: tenantNamespace},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef:     v1alpha1.GatewayReference{Name: "secure"},
			SecretRef:      v1alpha1.LocalObjectReference{Name: "secure-app-smtp"},
			AllowedSenders: []string{"*@example.test"},
		},
	}
	if err := c.Create(t.Context(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := c.Create(t.Context(), nodePortService("secure")); err != nil {
		t.Fatalf("create node port service: %v", err)
	}

	cl.waitForDeployment(t, "secure", 3*time.Minute)
	credentials := waitForAccountSecret(t, c, tenantNamespace, "secure-app-smtp", 2*time.Minute)

	// The certificate the gateway serves is the one cert-manager issued: this
	// only verifies if the operator mounted the right Secret at the right path
	// and the dataplane read it.
	const subject = "cert-manager issued listener"
	if err := waitForSuccessfulSubmission(t, cl.GatewaySMTPAddr, caPool,
		string(credentials.Data[corev1.BasicAuthUsernameKey]),
		string(credentials.Data[corev1.BasicAuthPasswordKey]),
		subject, 2*time.Minute); err != nil {
		cl.describeGatewayPods(t)
		t.Fatalf("submission over the cert-manager certificate failed: %v", err)
	}
	waitForMailpitMessage(t, cl.MailpitAPIURL, subject, time.Minute)

	// A client that does not trust the issuing CA must be turned away, which
	// confirms the gateway is not falling back to something self-signed.
	//
	// The check has to be made on a command, not on the dial: go-smtp calls
	// tls.Client without Handshake(), and a Go TLS handshake is lazy — so
	// DialStartTLS succeeds even against a certificate it cannot verify, and
	// the error only surfaces on the first read or write.
	untrusting, err := smtp.DialStartTLS(cl.GatewaySMTPAddr, &tls.Config{
		ServerName: gatewayCertName, MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		defer untrusting.Close()
		err = untrusting.Noop()
	}
	if err == nil {
		t.Fatal("the gateway was accepted by a client that trusts neither the CA nor anything else")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate verification failure, got %v", err)
	}
}

// selfSignedIssuer stands in for a real issuer. A CA issuer is used rather than
// a bare self-signed one so that the resulting Secret carries a ca.crt the
// client can trust.
const selfSignedIssuer = `
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: mailout-test-selfsigned
  namespace: mailout-system
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: mailout-test-ca
  namespace: mailout-system
spec:
  isCA: true
  commonName: mailout test CA
  secretName: mailout-test-ca
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: mailout-test-selfsigned
    kind: Issuer
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: mailout-test-ca
  namespace: mailout-system
spec:
  ca:
    secretName: mailout-test-ca
`

// waitForWebhook blocks until the validating webhook answers, which it only
// does once the operator serves TLS with a certificate the API server trusts.
func waitForWebhook(t *testing.T, c client.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		// A deliberately invalid object: a rejection from our own webhook is
		// proof it was reached, and nothing is left behind either way.
		probe := &v1alpha1.MailoutGateway{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook-probe", Namespace: operatorNamespace},
			Spec: v1alpha1.MailoutGatewaySpec{
				Upstream: v1alpha1.UpstreamSpec{Host: "probe.test", Port: 587},
			},
		}
		lastErr = c.Create(t.Context(), probe)
		if lastErr != nil && strings.Contains(lastErr.Error(), "certificateRefs or issuerRef") {
			return
		}
		if lastErr == nil {
			// Admitted: the webhook is not wired up yet. Clean up and retry.
			_ = c.Delete(t.Context(), probe)
			if apierrors.IsNotFound(lastErr) {
				lastErr = nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the validating webhook never answered within %s; last result: %v", timeout, lastErr)
}
