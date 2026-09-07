//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
			Hostname:  gatewayCertName,
			Listeners: v1alpha1.ListenersSpec{Submission: &v1alpha1.ListenerSpec{}},
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
	// A mounted Secret takes up to a kubelet sync period to change on disk, and
	// the gateway then reloads it; two minutes covers both.
	const rotatedSubject = "cluster relay after rotation"
	if err := waitForSuccessfulSubmission(t, cl.GatewaySMTPAddr, caPool, username, rotated,
		rotatedSubject, 2*time.Minute); err != nil {
		cl.describeGatewayPods(t)
		t.Fatalf("the rotated password never became usable: %v", err)
	}
	waitForMailpitMessage(t, cl.MailpitAPIURL, rotatedSubject, time.Minute)

	if podsAfter := gatewayPodNames(t, c); !sameStrings(podsBefore, podsAfter) {
		t.Fatalf("the gateway pods were replaced by a password rotation: %v -> %v",
			podsBefore, podsAfter)
	}
}

// submit authenticates and sends one message, the way an application would.
func submit(t *testing.T, addr string, caPool *x509.CertPool, username, password, subject string) error {
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
	body := fmt.Sprintf("From: app@example.test\r\nTo: dest@elsewhere.test\r\nSubject: %s\r\n\r\nsent through the cluster\r\n", subject)
	if err := client.SendMail("app@example.test", []string{"dest@elsewhere.test"},
		strings.NewReader(body)); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// waitForSuccessfulSubmission retries until the credentials are accepted.
func waitForSuccessfulSubmission(t *testing.T, addr string, caPool *x509.CertPool,
	username, password, subject string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = submit(t, addr, caPool, username, password, subject); lastErr == nil {
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

// waitForMailpitMessage returns the raw message with the given subject.
func waitForMailpitMessage(t *testing.T, apiURL, subject string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var payload struct {
			Messages []struct {
				ID      string
				Subject string
			}
		}
		if resp, err := http.Get(apiURL + "/api/v1/messages"); err == nil {
			err := json.NewDecoder(resp.Body).Decode(&payload)
			resp.Body.Close()
			if err == nil {
				for _, msg := range payload.Messages {
					if msg.Subject != subject {
						continue
					}
					raw, err := http.Get(apiURL + "/api/v1/message/" + msg.ID + "/raw")
					if err != nil {
						break
					}
					body, err := io.ReadAll(raw.Body)
					raw.Body.Close()
					if err == nil {
						return string(body)
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no message with subject %q reached the upstream within %s", subject, timeout)
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
