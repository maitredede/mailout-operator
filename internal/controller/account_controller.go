// Copyright (c) 2026 Damien Daly. All rights reserved.

package controller

import (
	"context"
	"fmt"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// AccountReconciler provisions one application's credentials: it generates the
// password, writes it to a Secret in the application's namespace, and keeps
// only the bcrypt hash — in that same Secret, next to the cleartext it belongs
// to.
type AccountReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// OperatorNamespace is where gateways live, and the default namespace of an
	// account's gatewayRef.
	OperatorNamespace string
}

// +kubebuilder:rbac:groups=mailout.daly.nc,resources=mailoutaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mailout.daly.nc,resources=mailoutaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mailout.daly.nc,resources=mailoutgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile brings one account to its desired state.
func (r *AccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var account v1alpha1.MailoutAccount
	if err := r.Get(ctx, req.NamespacedName, &account); err != nil {
		// The Secret is owned by the account, so deletion cleans up on its own.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	gatewayNamespace := GatewayNamespaceFor(&account, r.OperatorNamespace)
	var gw v1alpha1.MailoutGateway
	err := r.Get(ctx, client.ObjectKey{Namespace: gatewayNamespace, Name: account.Spec.GatewayRef.Name}, &gw)
	switch {
	case apierrors.IsNotFound(err):
		// Not an error: the gateway may be created later. The dataplane refuses
		// this account's logins in the meantime.
		return r.markNotAccepted(ctx, &account, v1alpha1.ReasonGatewayNotFound,
			fmt.Sprintf("MailoutGateway %s/%s not found", gatewayNamespace, account.Spec.GatewayRef.Name))
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get gateway: %w", err)
	}

	allowed, err := namespaceAllowed(ctx, r.Client, &gw, account.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !allowed {
		return r.markNotAccepted(ctx, &account, v1alpha1.ReasonNamespaceNotAllowed,
			fmt.Sprintf("MailoutGateway %s/%s does not accept accounts from namespace %s",
				gw.Namespace, gw.Name, account.Namespace))
	}

	username := UsernameFor(&account)
	if conflict, err := r.usernameConflict(ctx, &account, &gw, username); err != nil {
		return ctrl.Result{}, err
	} else if conflict != "" {
		return r.markNotAccepted(ctx, &account, v1alpha1.ReasonUsernameConflict,
			fmt.Sprintf("username %q is already used by MailoutAccount %s", username, conflict))
	}

	if err := r.reconcileSecret(ctx, &account, &gw, username); err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("account reconciled", "username", username, "gateway", gw.Name)
	return ctrl.Result{}, r.markReady(ctx, &account, &gw, username)
}

// reconcileSecret creates or updates the credentials Secret. The password is
// generated once and kept: it is only regenerated when spec.rotation changes,
// or when the Secret has gone missing.
func (r *AccountReconciler) reconcileSecret(ctx context.Context, account *v1alpha1.MailoutAccount,
	gw *v1alpha1.MailoutGateway, username string) error {
	log := logf.FromContext(ctx)

	cfg, err := render.GatewayConfig(render.Input{Gateway: gw})
	if err != nil {
		return fmt.Errorf("render gateway endpoint: %w", err)
	}
	endpoint := render.GatewayEndpoint(gw, cfg)

	secret := &corev1.Secret{}
	secret.Name = account.Spec.SecretRef.Name
	secret.Namespace = account.Namespace

	rotationChanged := account.Status.RotationObserved != account.Spec.Rotation
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		existingPassword := string(secret.Data[corev1.BasicAuthPasswordKey])
		existingHash := string(secret.Data[render.PasswordHashKey])

		password, hash := existingPassword, existingHash
		// A hash that is not one the gateway will serve is treated as absent
		// and replaced. The Secret lives in the tenant's namespace, so its
		// contents are not the operator's word: a hand-written $2a$31$ hash
		// would otherwise reach the shared configuration and make every AUTH
		// attempt on that username burn hours of CPU on every replica.
		if password == "" || hash == "" || rotationChanged || !gateway.UsableHash(hash) {
			password, err = gateway.GeneratePassword()
			if err != nil {
				return err
			}
			hash, err = gateway.HashPassword(password)
			if err != nil {
				return err
			}
			log.Info("password generated", "account", account.Name, "rotation", account.Spec.Rotation)
		}

		desired := render.AccountSecret(account, username, password, hash, endpoint, gw.Namespace)
		secret.Labels = desired.Labels
		secret.Type = desired.Type
		secret.Data = desired.Data
		return controllerutil.SetControllerReference(account, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile account secret: %w", err)
	}
	return nil
}

// usernameConflict reports the account already using this username on the same
// gateway, if any. Two accounts sharing a username would make authentication
// ambiguous, so the second one is refused rather than silently overriding.
func (r *AccountReconciler) usernameConflict(ctx context.Context, account *v1alpha1.MailoutAccount,
	gw *v1alpha1.MailoutGateway, username string) (string, error) {
	var accounts v1alpha1.MailoutAccountList
	if err := r.List(ctx, &accounts); err != nil {
		return "", fmt.Errorf("list accounts: %w", err)
	}
	for i := range accounts.Items {
		other := &accounts.Items[i]
		if other.Namespace == account.Namespace && other.Name == account.Name {
			continue
		}
		if GatewayNamespaceFor(other, r.OperatorNamespace) != gw.Namespace ||
			other.Spec.GatewayRef.Name != gw.Name {
			continue
		}
		if UsernameFor(other) != username {
			continue
		}
		// The older object keeps the name; creation order is what breaks the
		// tie, so the outcome does not depend on reconciliation order.
		if other.CreationTimestamp.Before(&account.CreationTimestamp) {
			return other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
}

func (r *AccountReconciler) markNotAccepted(ctx context.Context, account *v1alpha1.MailoutAccount,
	reason, message string) (ctrl.Result, error) {
	patch := client.MergeFrom(account.DeepCopy())
	account.Status.ObservedGeneration = account.Generation
	setCondition(&account.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionFalse, reason, message, account.Generation)
	setCondition(&account.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse, reason, message, account.Generation)
	return ctrl.Result{}, r.Status().Patch(ctx, account, patch)
}

func (r *AccountReconciler) markReady(ctx context.Context, account *v1alpha1.MailoutAccount,
	gw *v1alpha1.MailoutGateway, username string) error {
	patch := client.MergeFrom(account.DeepCopy())
	account.Status.ObservedGeneration = account.Generation
	account.Status.Username = username
	account.Status.SecretName = account.Spec.SecretRef.Name
	account.Status.Gateway = gw.Namespace + "/" + gw.Name
	account.Status.RotationObserved = account.Spec.Rotation

	setCondition(&account.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionTrue,
		v1alpha1.ReasonAccepted, "Account accepted by "+gw.Name, account.Generation)
	if account.Spec.Disabled {
		setCondition(&account.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse,
			v1alpha1.ReasonDisabled, "Account is disabled; authentication is refused", account.Generation)
	} else {
		setCondition(&account.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionTrue,
			v1alpha1.ReasonReady, "Credentials provisioned in Secret "+account.Spec.SecretRef.Name, account.Generation)
	}
	return r.Status().Patch(ctx, account, patch)
}

// SetupWithManager registers the controller.
func (r *AccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.MailoutAccount{}).
		Owns(&corev1.Secret{}).
		Named("mailoutaccount").
		Complete(r)
}
