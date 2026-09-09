//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/pki"
	"github.com/maitredede/mailout-operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestOperatorDeploysAWorkingRelay is the end of the chain: two custom
// resources go in, and a mail comes out of a pod the operator deployed.
//
// Nothing else proves this. The envtest suite checks what the operator writes;
// this checks that what it writes actually runs.
func TestOperatorDeploysAWorkingRelay(t *testing.T) {
	cl := startCluster(t)
	c := cl.Client

	// A certificate the gateway serves and the test trusts. In production this
	// comes from cert-manager; here it is issued on the spot.
	ca, err := pki.NewCA("mailout cluster test")
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
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-tls", Namespace: operatorNamespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": serverCert.CertPEM,
			"tls.key": serverCert.KeyPEM,
		},
	}); err != nil {
		t.Fatalf("create TLS secret: %v", err)
	}

	// A DKIM key, to check that signing works from a mounted Secret rather than
	// from an inlined PEM.
	dkimKey, err := gateway.GenerateDKIMKey("rsa", "example.test", "mail")
	if err != nil {
		t.Fatalf("GenerateDKIMKey: %v", err)
	}
	if err := c.Create(t.Context(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dkim-example", Namespace: operatorNamespace},
		Data:       map[string][]byte{"private.key": []byte(dkimKey.PrivateKeyPEM)},
	}); err != nil {
		t.Fatalf("create DKIM secret: %v", err)
	}

	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "relay", Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname: gatewayCertName,
			// The gateway grants the sending rights; an account can only narrow them.
			AllowedSenders: []v1alpha1.SenderGrantSpec{{Senders: []string{"*@example.test"}}},
			Listeners:      v1alpha1.ListenersSpec{Submission: &v1alpha1.ListenerSpec{}},
			TLS: v1alpha1.GatewayTLSSpec{
				CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "gateway-tls"}},
			},
			Upstream: v1alpha1.UpstreamSpec{
				Host: "mailpit.default.svc.cluster.local",
				Port: 1025,
				TLS:  v1alpha1.TLSModeNone,
			},
			DKIM: []v1alpha1.DKIMKeySpec{{
				Domain:              "example.test",
				Selector:            "mail",
				PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-example"},
			}},
			Deployment: v1alpha1.DeploymentSpec{Replicas: ptrTo(int32(1))},
		},
	}
	if err := c.Create(t.Context(), gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "invoicing", Namespace: tenantNamespace},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "relay"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "invoicing-smtp"},
			// Declaring the sender is what earns the DKIM signature asserted
			// below.
			AllowedSenders: []string{"*@example.test"},
		},
	}
	if err := c.Create(t.Context(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}

	// The test owns the node port, since the operator deliberately does not
	// manage them.
	if err := c.Create(t.Context(), nodePortService("relay")); err != nil {
		t.Fatalf("create node port service: %v", err)
	}

	// An available replica means the readiness probe connected to the SMTP
	// port, which means the rendered configuration was accepted.
	cl.waitForDeployment(t, "relay", 3*time.Minute)

	credentials := waitForAccountSecret(t, c, tenantNamespace, "invoicing-smtp", time.Minute)
	username := string(credentials.Data[corev1.BasicAuthUsernameKey])
	password := string(credentials.Data[corev1.BasicAuthPasswordKey])
	if username != tenantNamespace+".invoicing" || password == "" {
		t.Fatalf("unexpected credentials: username=%q password set=%v", username, password != "")
	}
	// The endpoint in the Secret must be the in-cluster address of the gateway.
	if host := string(credentials.Data["host"]); host != "relay."+operatorNamespace+".svc" {
		t.Fatalf("host = %q", host)
	}

	// Now use exactly those credentials, the way an application would. Retried
	// for a while: the node port only becomes reachable once kube-proxy has
	// programmed the rule for the newly ready pod.
	const subject = "cluster relay"
	if err := waitForSuccessfulSubmission(t, cl.GatewaySMTPAddr, caPool, username, password,
		subject, time.Minute); err != nil {
		cl.describeGatewayPods(t)
		t.Fatalf("submission through the deployed gateway failed: %v", err)
	}

	raw := waitForMailpitMessage(t, cl.MailpitAPIURL, subject, time.Minute)
	if !strings.Contains(raw, "with ESMTPSA id "+username) {
		t.Fatalf("the gateway's Received header is missing:\n%s", raw)
	}

	// The key came from a mounted Secret, so a valid signature also proves the
	// mount path the operator rendered is the one the dataplane reads.
	lookup := func(name string) ([]string, error) {
		if name != "mail._domainkey.example.test" {
			return nil, fmt.Errorf("unexpected lookup for %q", name)
		}
		return []string{dkimKey.DNSRecordValue}, nil
	}
	verifications, err := dkim.VerifyWithOptions(strings.NewReader(raw),
		&dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil || len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("the relayed message is not properly signed: %v %+v\n%s", err, verifications, raw)
	}

	// The endpoint the ServiceMonitor would point at must actually serve, in a
	// real pod, with the flag the operator rendered. And it must have counted
	// the message that just went through: a metrics port that is open but wired
	// to nothing looks identical from the outside.
	//
	// The token comes from the same Secret key the ServiceMonitor references,
	// so this also checks the two halves of the credential match: the operator
	// generated one value, put it in the configuration the pod reads, and
	// published it where Prometheus is told to look.
	var configSecret corev1.Secret
	if err := c.Get(t.Context(), client.ObjectKey{
		Namespace: operatorNamespace, Name: render.ConfigSecretName(gw.Name),
	}, &configSecret); err != nil {
		t.Fatalf("get the gateway configuration secret: %v", err)
	}
	metricsToken := string(configSecret.Data[render.MetricsTokenKey])
	if metricsToken == "" {
		t.Fatal("the configuration secret carries no metrics token for Prometheus to present")
	}
	if code := scrapeStatus(t, cl.MetricsURL, "", time.Minute); code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated scrape got %d, want 401: the endpoint lists the accounts "+
			"served and the domains signed", code)
	}
	metrics := scrapeMetrics(t, cl.MetricsURL, metricsToken, time.Minute)
	wantSeries := fmt.Sprintf("mailout_messages_total{account=%q,result=%q} 1", username, gateway.ResultRelayed)
	if !strings.Contains(metrics, wantSeries) {
		t.Errorf("the relayed message was not counted; wanted %s in:\n%s", wantSeries, metrics)
	}
	if !strings.Contains(metrics, "mailout_accounts 1") {
		t.Errorf("the served-account gauge is missing:\n%s", metrics)
	}

	// And the status must reflect what happened.
	var fresh v1alpha1.MailoutGateway
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), &fresh); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, v1alpha1.ConditionReady) {
		t.Fatalf("the gateway is serving but not Ready: %+v", fresh.Status.Conditions)
	}
	if fresh.Status.AcceptedAccounts != 1 {
		t.Fatalf("acceptedAccounts = %d", fresh.Status.AcceptedAccounts)
	}

	// A wrong password must be refused by the deployed gateway too.
	if err := submit(t, cl.GatewaySMTPAddr, caPool, username, "wrong-password", "rejected"); err == nil {
		t.Fatal("the deployed gateway accepted a wrong password")
	}

	// Rotating the password must produce credentials that work, without the pod
	// being restarted: the gateway reloads its accounts from the mounted Secret.
	podsBefore := gatewayPodNames(t, c)
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(account), account); err != nil {
		t.Fatalf("get account: %v", err)
	}
	account.Spec.Rotation = "rotated-once"
	if err := c.Update(t.Context(), account); err != nil {
		t.Fatalf("update rotation: %v", err)
	}

	rotated := waitForNewPassword(t, c, tenantNamespace, "invoicing-smtp", password, time.Minute)

	// The published configuration must pick up the new hash promptly: the
	// account's Secret belongs to the account, so this only happens because the
	// gateway controller watches it by label rather than waiting for its resync.
	cl.waitForPublishedHash(t, "relay", tenantNamespace, "invoicing-smtp", time.Minute)

	// From there it is Kubernetes' own latency: a mounted Secret changes on disk
	// after the kubelet's sync period plus its cache TTL, and the gateway then
	// reloads it. Four minutes covers the documented worst case.
	const rotatedSubject = "cluster relay after rotation"
	if err := waitForSuccessfulSubmission(t, cl.GatewaySMTPAddr, caPool, username, rotated,
		rotatedSubject, 4*time.Minute); err != nil {
		cl.describeGatewayPods(t)
		t.Fatalf("the rotated password never became usable: %v", err)
	}
	waitForMailpitMessage(t, cl.MailpitAPIURL, rotatedSubject, time.Minute)

	if podsAfter := gatewayPodNames(t, c); !sameStrings(podsBefore, podsAfter) {
		t.Fatalf("the gateway pods were replaced by a password rotation: %v -> %v",
			podsBefore, podsAfter)
	}
}

// submit sends one message with a From header matching its envelope, the way an
// application would.
func submit(t *testing.T, addr string, caPool *x509.CertPool, username, password, subject string) error {
	t.Helper()
	return submitAs(t, addr, caPool, username, password, subject, "app@example.test", "app@example.test")
}

// submitAs sends one message with the envelope sender and the From header set
// independently, which is what a spoofing attempt looks like.
func submitAs(t *testing.T, addr string, caPool *x509.CertPool, username, password,
	subject, envelopeFrom, headerFrom string) error {
	t.Helper()
	client, err := smtp.DialStartTLS(addr, &tls.Config{
		ServerName: gatewayCertName, RootCAs: caPool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer client.Close()
	if err := client.Auth(sasl.NewPlainClient("", username, password)); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	body := fmt.Sprintf("From: %s\r\nTo: dest@elsewhere.test\r\nSubject: %s\r\n\r\nsent through the cluster\r\n",
		headerFrom, subject)
	if err := client.SendMail(envelopeFrom, []string{"dest@elsewhere.test"},
		strings.NewReader(body)); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// waitForSuccessfulSubmission retries until the credentials are accepted, with
// a From matching the envelope.
func waitForSuccessfulSubmission(t *testing.T, addr string, caPool *x509.CertPool,
	username, password, subject string, timeout time.Duration) error {
	t.Helper()
	return waitForSuccessfulSubmissionAs(t, addr, caPool, username, password, subject,
		"app@example.test", "app@example.test", timeout)
}

// waitForSuccessfulSubmissionAs retries a submission with explicit sender
// addresses. Retrying is needed because a node port only becomes reachable once
// kube-proxy has programmed the rule for the newly ready pod — a refusal by the
// sender policy would simply be retried until the deadline, which is why the
// callers that expect a refusal assert on a single attempt instead.
func waitForSuccessfulSubmissionAs(t *testing.T, addr string, caPool *x509.CertPool,
	username, password, subject, envelopeFrom, headerFrom string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = submitAs(t, addr, caPool, username, password, subject, envelopeFrom, headerFrom)
		if lastErr == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return lastErr
}

func waitForAccountSecret(t *testing.T, c client.Client, namespace, name string, timeout time.Duration) *corev1.Secret {
	t.Helper()
	deadline := time.Now().Add(timeout)
	key := client.ObjectKey{Namespace: namespace, Name: name}
	for time.Now().Before(deadline) {
		var secret corev1.Secret
		if err := c.Get(t.Context(), key, &secret); err == nil {
			if len(secret.Data[render.PasswordHashKey]) > 0 {
				return &secret
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the account Secret %s was not provisioned within %s", key, timeout)
	return nil
}

// waitForNewPassword blocks until the Secret carries a password other than the
// one given.
func waitForNewPassword(t *testing.T, c client.Client, namespace, name, previous string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	key := client.ObjectKey{Namespace: namespace, Name: name}
	for time.Now().Before(deadline) {
		var secret corev1.Secret
		if err := c.Get(t.Context(), key, &secret); err == nil {
			if current := string(secret.Data[corev1.BasicAuthPasswordKey]); current != previous && current != "" {
				return current
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the password was not rotated within %s", timeout)
	return ""
}

func gatewayPodNames(t *testing.T, c client.Client) []string {
	t.Helper()
	var pods corev1.PodList
	if err := c.List(t.Context(), &pods, client.InNamespace(operatorNamespace),
		client.MatchingLabels(render.SelectorLabels("relay"))); err != nil {
		t.Fatalf("list gateway pods: %v", err)
	}
	names := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		names = append(names, pods.Items[i].Name)
	}
	return names
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ptrTo[T any](v T) *T { return &v }
