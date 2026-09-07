//go:build envtest

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package controller

import (
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/render"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newGateway(t *testing.T, c client.Client, name string, mutate ...func(*v1alpha1.MailoutGateway)) *v1alpha1.MailoutGateway {
	t.Helper()
	gw := &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operatorNamespace},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname: "mail.example.test",
			TLS: v1alpha1.GatewayTLSSpec{
				CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "mail-tls"}},
			},
			Upstream: v1alpha1.UpstreamSpec{Host: "smtp.upstream.test", Port: 587, TLS: v1alpha1.TLSModeStartTLS},
		},
	}
	for _, m := range mutate {
		m(gw)
	}
	if err := c.Create(t.Context(), gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	return gw
}

func newAccount(t *testing.T, c client.Client, namespace, name, gatewayName string,
	mutate ...func(*v1alpha1.MailoutAccount)) *v1alpha1.MailoutAccount {
	t.Helper()
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: gatewayName},
			SecretRef:  v1alpha1.LocalObjectReference{Name: name + "-smtp"},
		},
	}
	for _, m := range mutate {
		m(account)
	}
	if err := c.Create(t.Context(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}
	return account
}

func newAccountReconciler(c client.Client) *AccountReconciler {
	return &AccountReconciler{Client: c, Scheme: scheme, OperatorNamespace: operatorNamespace}
}

func reconcileAccount(t *testing.T, r *AccountReconciler, account *v1alpha1.MailoutAccount) {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(account),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func getSecret(t *testing.T, c client.Client, namespace, name string) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: name}, &secret); err != nil {
		t.Fatalf("get secret %s/%s: %v", namespace, name, err)
	}
	return &secret
}

func refreshAccount(t *testing.T, c client.Client, account *v1alpha1.MailoutAccount) *v1alpha1.MailoutAccount {
	t.Helper()
	var fresh v1alpha1.MailoutAccount
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(account), &fresh); err != nil {
		t.Fatalf("get account: %v", err)
	}
	return &fresh
}

func TestAccountProvisionsCredentials(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "provision")
	ns := newNamespace(t, c, "billing")
	account := newAccount(t, c, ns, "invoicing", gw.Name)

	reconcileAccount(t, newAccountReconciler(c), account)

	secret := getSecret(t, c, ns, "invoicing-smtp")
	if secret.Type != corev1.SecretTypeBasicAuth {
		t.Fatalf("secret type = %q", secret.Type)
	}
	username := string(secret.Data[corev1.BasicAuthUsernameKey])
	if username != ns+".invoicing" {
		t.Fatalf("username = %q, want %s.invoicing", username, ns)
	}
	password := string(secret.Data[corev1.BasicAuthPasswordKey])
	if password == "" {
		t.Fatal("no password generated")
	}
	// The hash must actually match the cleartext, or the dataplane would refuse
	// the very credentials it just handed out.
	hash := secret.Data[render.PasswordHashKey]
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Fatalf("the stored hash does not match the generated password: %v", err)
	}
	if got := string(secret.Data["host"]); got != "provision."+operatorNamespace+".svc" {
		t.Fatalf("host = %q", got)
	}
	if got := string(secret.Data["port"]); got != "587" {
		t.Fatalf("port = %q", got)
	}

	// The Secret must be owned by the account, so deleting the account cleans up.
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Name != "invoicing" {
		t.Fatalf("owner references = %+v", secret.OwnerReferences)
	}

	fresh := refreshAccount(t, c, account)
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatalf("not accepted: %+v", fresh.Status.Conditions)
	}
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, v1alpha1.ConditionReady) {
		t.Fatalf("not ready: %+v", fresh.Status.Conditions)
	}
	if fresh.Status.Username != username || fresh.Status.SecretName != "invoicing-smtp" {
		t.Fatalf("status = %+v", fresh.Status)
	}
}

// Reconciling again must not touch the password: a stable reconciliation is
// what keeps an application's credentials working.
func TestAccountPasswordIsStableAcrossReconciles(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "stable")
	ns := newNamespace(t, c, "app")
	account := newAccount(t, c, ns, "stable", gw.Name)

	r := newAccountReconciler(c)
	reconcileAccount(t, r, account)
	first := string(getSecret(t, c, ns, "stable-smtp").Data[corev1.BasicAuthPasswordKey])

	reconcileAccount(t, r, refreshAccount(t, c, account))
	second := string(getSecret(t, c, ns, "stable-smtp").Data[corev1.BasicAuthPasswordKey])

	if first != second {
		t.Fatal("the password changed without a rotation being asked for")
	}
}

// Changing spec.rotation is the documented way to get a new password.
func TestAccountRotationRegeneratesThePassword(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "rotation")
	ns := newNamespace(t, c, "app")
	account := newAccount(t, c, ns, "rotating", gw.Name, func(a *v1alpha1.MailoutAccount) {
		a.Spec.Rotation = "first"
	})

	r := newAccountReconciler(c)
	reconcileAccount(t, r, account)
	before := string(getSecret(t, c, ns, "rotating-smtp").Data[corev1.BasicAuthPasswordKey])

	account = refreshAccount(t, c, account)
	account.Spec.Rotation = "second"
	if err := c.Update(t.Context(), account); err != nil {
		t.Fatalf("update rotation: %v", err)
	}
	reconcileAccount(t, r, account)

	secret := getSecret(t, c, ns, "rotating-smtp")
	after := string(secret.Data[corev1.BasicAuthPasswordKey])
	if before == after {
		t.Fatal("the password did not change after a rotation")
	}
	if err := bcrypt.CompareHashAndPassword(secret.Data[render.PasswordHashKey], []byte(after)); err != nil {
		t.Fatalf("hash not updated with the new password: %v", err)
	}
	if got := refreshAccount(t, c, account).Status.RotationObserved; got != "second" {
		t.Fatalf("rotationObserved = %q", got)
	}
}

// A missing gateway is a state to report, not an error to retry blindly.
func TestAccountWithoutGatewayIsNotAccepted(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	ns := newNamespace(t, c, "orphan")
	account := newAccount(t, c, ns, "orphan", "no-such-gateway")

	reconcileAccount(t, newAccountReconciler(c), account)

	fresh := refreshAccount(t, c, account)
	condition := meta.FindStatusCondition(fresh.Status.Conditions, v1alpha1.ConditionAccepted)
	if condition == nil || condition.Status != metav1.ConditionFalse {
		t.Fatalf("conditions = %+v", fresh.Status.Conditions)
	}
	if condition.Reason != v1alpha1.ReasonGatewayNotFound {
		t.Fatalf("reason = %q", condition.Reason)
	}
	// No credentials must be handed out for an account that is not accepted.
	var secret corev1.Secret
	err := c.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: "orphan-smtp"}, &secret)
	if err == nil {
		t.Fatal("a Secret was created for an account with no gateway")
	}
}

// A gateway restricted to its own namespace must refuse a foreign account.
func TestAccountRefusedWhenNamespaceNotAllowed(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "restricted", func(g *v1alpha1.MailoutGateway) {
		g.Spec.AllowedAccounts = v1alpha1.AllowedAccountsSpec{Namespaces: v1alpha1.NamespacesFromSame}
	})
	ns := newNamespace(t, c, "tenant")
	account := newAccount(t, c, ns, "outsider", gw.Name)

	reconcileAccount(t, newAccountReconciler(c), account)

	fresh := refreshAccount(t, c, account)
	condition := meta.FindStatusCondition(fresh.Status.Conditions, v1alpha1.ConditionAccepted)
	if condition == nil || condition.Reason != v1alpha1.ReasonNamespaceNotAllowed {
		t.Fatalf("conditions = %+v", fresh.Status.Conditions)
	}
}

// A namespace selector lets the gateway's owner grant access by label.
func TestAccountAcceptedByNamespaceSelector(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "selective", func(g *v1alpha1.MailoutGateway) {
		g.Spec.AllowedAccounts = v1alpha1.AllowedAccountsSpec{
			Namespaces: v1alpha1.NamespacesFromSelector,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"mailout": "allowed"},
			},
		}
	})

	allowedNS := newNamespace(t, c, "allowed")
	var ns corev1.Namespace
	if err := c.Get(t.Context(), client.ObjectKey{Name: allowedNS}, &ns); err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	ns.Labels = map[string]string{"mailout": "allowed"}
	if err := c.Update(t.Context(), &ns); err != nil {
		t.Fatalf("label namespace: %v", err)
	}

	r := newAccountReconciler(c)
	allowed := newAccount(t, c, allowedNS, "inside", gw.Name)
	reconcileAccount(t, r, allowed)
	if !meta.IsStatusConditionTrue(refreshAccount(t, c, allowed).Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatal("a labelled namespace should be accepted")
	}

	deniedNS := newNamespace(t, c, "denied")
	denied := newAccount(t, c, deniedNS, "outside", gw.Name)
	reconcileAccount(t, r, denied)
	if meta.IsStatusConditionTrue(refreshAccount(t, c, denied).Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatal("an unlabelled namespace should be refused")
	}
}

// Two accounts claiming one username would make authentication ambiguous.
func TestAccountUsernameConflictIsRefused(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "conflict")
	first := newNamespace(t, c, "first")
	second := newNamespace(t, c, "second")

	r := newAccountReconciler(c)
	winner := newAccount(t, c, first, "a", gw.Name, func(a *v1alpha1.MailoutAccount) {
		a.Spec.Username = "shared@example.test"
	})
	reconcileAccount(t, r, winner)

	// Kubernetes creation timestamps have a one-second granularity, and the
	// tie-break is on creation order, so the second account must be created
	// strictly later for this test to mean anything.
	time.Sleep(1100 * time.Millisecond)
	loser := newAccount(t, c, second, "b", gw.Name, func(a *v1alpha1.MailoutAccount) {
		a.Spec.Username = "shared@example.test"
	})
	reconcileAccount(t, r, loser)

	if !meta.IsStatusConditionTrue(refreshAccount(t, c, winner).Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatal("the first account should keep the username")
	}
	condition := meta.FindStatusCondition(refreshAccount(t, c, loser).Status.Conditions, v1alpha1.ConditionAccepted)
	if condition == nil || condition.Reason != v1alpha1.ReasonUsernameConflict {
		t.Fatalf("the second account should be refused, got %+v", condition)
	}
}

// A disabled account keeps its Secret but is not ready: the dataplane refuses
// its logins.
func TestDisabledAccountIsNotReady(t *testing.T) {
	c := newTestClient(t)
	ensureOperatorNamespace(t, c)
	gw := newGateway(t, c, "disabled")
	ns := newNamespace(t, c, "app")
	account := newAccount(t, c, ns, "off", gw.Name, func(a *v1alpha1.MailoutAccount) {
		a.Spec.Disabled = true
	})

	reconcileAccount(t, newAccountReconciler(c), account)

	fresh := refreshAccount(t, c, account)
	if !meta.IsStatusConditionTrue(fresh.Status.Conditions, v1alpha1.ConditionAccepted) {
		t.Fatal("a disabled account is still accepted")
	}
	condition := meta.FindStatusCondition(fresh.Status.Conditions, v1alpha1.ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != v1alpha1.ReasonDisabled {
		t.Fatalf("ready condition = %+v", condition)
	}
	// The Secret stays, so re-enabling does not change the password.
	getSecret(t, c, ns, "off-smtp")
}
