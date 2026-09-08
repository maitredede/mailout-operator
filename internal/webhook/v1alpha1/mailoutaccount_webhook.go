// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	"context"
	"fmt"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/controller"
	"github.com/maitredede/mailout-operator/internal/gateway"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-mailout-daly-nc-v1alpha1-mailoutaccount,mutating=false,failurePolicy=Fail,sideEffects=None,groups=mailout.daly.nc,resources=mailoutaccounts,verbs=create;update,versions=v1alpha1,name=vmailoutaccount.mailout.daly.nc,admissionReviewVersions=v1

// AccountValidator refuses accounts the operator could not provision, so that
// the mistake surfaces at kubectl apply time rather than in a status field
// nobody is watching.
type AccountValidator struct {
	// Reader is uncached: it must see Secrets the operator does not own, to
	// avoid overwriting one that belongs to someone else.
	Reader client.Reader
	// OperatorNamespace is the default namespace of an account's gatewayRef.
	OperatorNamespace string
}

var _ admission.Validator[*v1alpha1.MailoutAccount] = &AccountValidator{}

// SetupAccountWebhookWithManager registers the validator.
func SetupAccountWebhookWithManager(mgr ctrl.Manager, operatorNamespace string) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1alpha1.MailoutAccount{}).
		WithValidator(&AccountValidator{
			Reader:            mgr.GetAPIReader(),
			OperatorNamespace: operatorNamespace,
		}).
		Complete()
}

// ValidateCreate validates a new account.
func (v *AccountValidator) ValidateCreate(ctx context.Context, account *v1alpha1.MailoutAccount) (admission.Warnings, error) {
	return v.validate(ctx, account)
}

// ValidateUpdate validates a change.
func (v *AccountValidator) ValidateUpdate(ctx context.Context, _, account *v1alpha1.MailoutAccount) (admission.Warnings, error) {
	return v.validate(ctx, account)
}

// ValidateDelete allows every deletion; the Secret goes with the account.
func (v *AccountValidator) ValidateDelete(context.Context, *v1alpha1.MailoutAccount) (admission.Warnings, error) {
	return nil, nil
}

func (v *AccountValidator) validate(ctx context.Context, account *v1alpha1.MailoutAccount) (admission.Warnings, error) {
	var errs field.ErrorList
	var warnings admission.Warnings
	spec := field.NewPath("spec")

	if len(account.Spec.AllowedSenders) == 0 {
		warnings = append(warnings, "spec.allowedSenders is empty: this account may send from "+
			"any address, and its mail will not be DKIM-signed at all")
	}
	if account.Spec.EnforceHeaderFrom != nil && !*account.Spec.EnforceHeaderFrom {
		warnings = append(warnings, "spec.enforceHeaderFrom is false: this account may put any "+
			"address in the From header its recipients will see")
	}

	gatewayNamespace := controller.GatewayNamespaceFor(account, v.OperatorNamespace)
	gatewayKey := client.ObjectKey{Namespace: gatewayNamespace, Name: account.Spec.GatewayRef.Name}

	var gw v1alpha1.MailoutGateway
	err := v.Reader.Get(ctx, gatewayKey, &gw)
	switch {
	case apierrors.IsNotFound(err):
		errs = append(errs, field.Invalid(spec.Child("gatewayRef"), gatewayKey.String(),
			"no such MailoutGateway; an account cannot be provisioned without one"))
	case err != nil:
		// A lookup failure is not the user's fault; refusing the write is
		// better than admitting something that cannot be checked.
		return nil, fmt.Errorf("look up gateway %s: %w", gatewayKey, err)
	default:
		errs = append(errs, v.validateAgainstGateway(ctx, account, &gw, spec)...)
	}

	// The CRD bounds spec.username, but not the default computed from the
	// namespace and the object name — and that default is what most accounts
	// actually get. Checking the effective value here is what makes a namespace
	// or an object name too long for a username fail at kubectl apply, instead
	// of leaving the account silently dropped from the served configuration.
	if username := controller.UsernameFor(account); !gateway.ValidUsername(username) {
		path := spec.Child("username")
		detail := fmt.Sprintf("must be at most %d printable ASCII characters, "+
			"without space, colon, semicolon, comma, quote or backslash", gateway.MaxUsernameLength)
		if account.Spec.Username == "" {
			detail = fmt.Sprintf("the default username %q is not usable: %s. Set spec.username explicitly.",
				username, detail)
			path = field.NewPath("metadata", "name")
		}
		errs = append(errs, field.Invalid(path, username, detail))
	}

	errs = append(errs, validateAllowedSenders(account.Spec.AllowedSenders, spec.Child("allowedSenders"))...)
	errs = append(errs, v.validateSecretRef(ctx, account, spec.Child("secretRef"))...)

	if len(errs) > 0 {
		return warnings, apierrors.NewInvalid(account.GroupVersionKind().GroupKind(), account.Name, errs)
	}
	return warnings, nil
}

// validateAgainstGateway checks what only the gateway can answer: whether this
// namespace may attach, and whether the username is free.
func (v *AccountValidator) validateAgainstGateway(ctx context.Context, account *v1alpha1.MailoutAccount,
	gw *v1alpha1.MailoutGateway, spec *field.Path) field.ErrorList {
	var errs field.ErrorList

	from := gw.Spec.AllowedAccounts.Namespaces
	if from == v1alpha1.NamespacesFromSame && account.Namespace != gw.Namespace {
		errs = append(errs, field.Forbidden(spec.Child("gatewayRef"),
			fmt.Sprintf("MailoutGateway %s/%s only accepts accounts from its own namespace",
				gw.Namespace, gw.Name)))
	}

	username := controller.UsernameFor(account)
	var accounts v1alpha1.MailoutAccountList
	if err := v.Reader.List(ctx, &accounts); err != nil {
		// Cannot enumerate: leave the conflict to the controller, which reports
		// it in status rather than blocking the write.
		return errs
	}
	for i := range accounts.Items {
		other := &accounts.Items[i]
		if other.Namespace == account.Namespace && other.Name == account.Name {
			continue
		}
		if controller.GatewayNamespaceFor(other, v.OperatorNamespace) != gw.Namespace ||
			other.Spec.GatewayRef.Name != gw.Name {
			continue
		}
		if controller.UsernameFor(other) == username {
			errs = append(errs, field.Duplicate(spec.Child("username"),
				fmt.Sprintf("%s is already used by MailoutAccount %s/%s on this gateway",
					username, other.Namespace, other.Name)))
			break
		}
	}
	return errs
}

// validateSecretRef refuses to take over a Secret the operator does not
// already own: the reconciliation overwrites its contents, which would destroy
// whatever was there.
func (v *AccountValidator) validateSecretRef(ctx context.Context, account *v1alpha1.MailoutAccount,
	path *field.Path) field.ErrorList {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: account.Namespace, Name: account.Spec.SecretRef.Name}
	if err := v.Reader.Get(ctx, key, &secret); err != nil {
		// Absent is the normal case, and a lookup failure must not block the
		// write on its own.
		return nil
	}
	for _, owner := range secret.OwnerReferences {
		if owner.Kind == "MailoutAccount" && owner.Name == account.Name {
			return nil
		}
	}
	if secret.Labels["app.kubernetes.io/managed-by"] == "mailout-operator" {
		return nil
	}
	return field.ErrorList{field.Invalid(path.Child("name"), account.Spec.SecretRef.Name,
		"a Secret with this name already exists and is not managed by mailout; "+
			"the operator would overwrite it, so pick another name")}
}
