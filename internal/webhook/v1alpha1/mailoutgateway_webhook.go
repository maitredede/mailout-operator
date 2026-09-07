// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

// Package v1alpha1 validates the mailout API objects at admission time, so that
// a mistake is reported when it is made rather than discovered later in a
// status field.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-mailout-daly-nc-v1alpha1-mailoutgateway,mutating=false,failurePolicy=Fail,sideEffects=None,groups=mailout.daly.nc,resources=mailoutgateways,verbs=create;update,versions=v1alpha1,name=vmailoutgateway.mailout.daly.nc,admissionReviewVersions=v1

// GatewayValidator rejects gateway definitions the operator could not serve.
type GatewayValidator struct {
	// OperatorNamespace is the only namespace whose gateways are served.
	OperatorNamespace string
	// CertManagerAvailable gates the use of spec.tls.issuerRef.
	CertManagerAvailable bool
}

var _ admission.Validator[*v1alpha1.MailoutGateway] = &GatewayValidator{}

// SetupGatewayWebhookWithManager registers the validator.
func SetupGatewayWebhookWithManager(mgr ctrl.Manager, operatorNamespace string, certManagerAvailable bool) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1alpha1.MailoutGateway{}).
		WithValidator(&GatewayValidator{
			OperatorNamespace:    operatorNamespace,
			CertManagerAvailable: certManagerAvailable,
		}).
		Complete()
}

// ValidateCreate validates a new gateway.
func (v *GatewayValidator) ValidateCreate(_ context.Context, gw *v1alpha1.MailoutGateway) (admission.Warnings, error) {
	return v.validate(gw)
}

// ValidateUpdate validates a change.
func (v *GatewayValidator) ValidateUpdate(_ context.Context, _, gw *v1alpha1.MailoutGateway) (admission.Warnings, error) {
	return v.validate(gw)
}

// ValidateDelete allows every deletion. Accounts referencing the gateway are
// not blocked: they report Accepted=False and the dataplane answers a temporary
// failure, which is recoverable if the gateway comes back.
func (v *GatewayValidator) ValidateDelete(_ context.Context, _ *v1alpha1.MailoutGateway) (admission.Warnings, error) {
	return nil, nil
}

func (v *GatewayValidator) validate(gw *v1alpha1.MailoutGateway) (admission.Warnings, error) {
	var errs field.ErrorList
	var warnings admission.Warnings
	spec := field.NewPath("spec")

	if gw.Namespace != v.OperatorNamespace {
		errs = append(errs, field.Forbidden(field.NewPath("metadata", "namespace"),
			fmt.Sprintf("gateways are only served in the operator namespace (%s); "+
				"serving one from a tenant namespace would put its upstream credentials within that tenant's reach",
				v.OperatorNamespace)))
	}

	errs = append(errs, v.validateTLS(gw, spec.Child("tls"))...)
	errs = append(errs, validateMilters(gw.Spec.Milters, spec.Child("milters"))...)
	errs = append(errs, validateDKIM(gw.Spec.DKIM, spec.Child("dkim"))...)
	errs = append(errs, v.validateListeners(gw, spec.Child("listeners"))...)

	if gw.Spec.AllowedAccounts.Namespaces == v1alpha1.NamespacesFromSelector &&
		gw.Spec.AllowedAccounts.Selector == nil {
		errs = append(errs, field.Required(spec.Child("allowedAccounts", "selector"),
			"required when namespaces is Selector"))
	}

	if gw.Spec.Upstream.TLS == v1alpha1.TLSModeNone {
		warnings = append(warnings, "spec.upstream.tls is None: mail leaves this gateway in clear, "+
			"including the credentials used towards the upstream server")
	}
	if gw.Spec.Upstream.InsecureSkipVerify {
		warnings = append(warnings, "spec.upstream.insecureSkipVerify is set: the upstream certificate "+
			"is not verified, so the connection can be intercepted")
	}
	for i, m := range gw.Spec.Milters {
		if m.FailOpen {
			warnings = append(warnings, fmt.Sprintf(
				"spec.milters[%d] (%s) has failOpen: mail goes out unfiltered when this filter is down",
				i, m.Name))
		}
	}

	if len(errs) > 0 {
		return warnings, apierrors.NewInvalid(
			gw.GroupVersionKind().GroupKind(), gw.Name, errs)
	}
	return warnings, nil
}

func (v *GatewayValidator) validateTLS(gw *v1alpha1.MailoutGateway, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	tls := gw.Spec.TLS

	switch {
	case len(tls.CertificateRefs) > 0 && tls.IssuerRef != nil:
		errs = append(errs, field.Invalid(path, "certificateRefs and issuerRef",
			"give either certificateRefs, to bring your own Secrets, or issuerRef, "+
				"to let the operator create a cert-manager Certificate — not both"))
	case len(tls.CertificateRefs) == 0 && tls.IssuerRef == nil:
		errs = append(errs, field.Required(path,
			"either certificateRefs or issuerRef is required: clients authenticate on "+
				"this gateway, so it never listens without TLS"))
	}

	if tls.IssuerRef != nil {
		if !v.CertManagerAvailable {
			errs = append(errs, field.Invalid(path.Child("issuerRef"), tls.IssuerRef.Name,
				"cert-manager is not installed in this cluster; bring your own certificate "+
					"Secrets with certificateRefs instead"))
		}
		if len(tls.DNSNames) == 0 && gw.Spec.Hostname == "" {
			errs = append(errs, field.Required(path.Child("dnsNames"),
				"required with issuerRef, unless spec.hostname is set"))
		}
	}

	if tls.DefaultCertificate != "" {
		found := false
		for _, ref := range tls.CertificateRefs {
			if ref.Name == tls.DefaultCertificate {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, field.Invalid(path.Child("defaultCertificate"), tls.DefaultCertificate,
				"must name one of spec.tls.certificateRefs"))
		}
	}

	seen := map[string]bool{}
	for i, ref := range tls.CertificateRefs {
		if seen[ref.Name] {
			errs = append(errs, field.Duplicate(path.Child("certificateRefs").Index(i), ref.Name))
		}
		seen[ref.Name] = true
	}
	return errs
}

func (v *GatewayValidator) validateListeners(gw *v1alpha1.MailoutGateway, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	submission, smtps := gw.Spec.Listeners.Submission, gw.Spec.Listeners.SMTPS
	if submission == nil || smtps == nil {
		return errs
	}
	submissionPort := submission.Port
	if submissionPort == 0 {
		submissionPort = 587
	}
	smtpsPort := smtps.Port
	if smtpsPort == 0 {
		smtpsPort = 465
	}
	if submissionPort == smtpsPort {
		errs = append(errs, field.Invalid(path.Child("smtps", "port"), smtpsPort,
			"the two listeners cannot share a port"))
	}
	return errs
}

func validateMilters(milters []v1alpha1.MilterSpec, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	seen := map[string]bool{}
	for i, m := range milters {
		if seen[m.Name] {
			errs = append(errs, field.Duplicate(path.Index(i).Child("name"), m.Name))
		}
		seen[m.Name] = true
		// Reuse the dataplane's own parser, so what the webhook accepts is
		// exactly what the gateway can dial.
		if _, _, err := (gateway.Milter{Address: m.Address}).ParseAddress(); err != nil {
			errs = append(errs, field.Invalid(path.Index(i).Child("address"), m.Address, err.Error()))
		}
	}
	return errs
}

func validateDKIM(keys []v1alpha1.DKIMKeySpec, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	seen := map[string]bool{}
	for i, k := range keys {
		domain := strings.ToLower(k.Domain)
		if seen[domain] {
			errs = append(errs, field.Duplicate(path.Index(i).Child("domain"), k.Domain))
		}
		seen[domain] = true
		if k.PrivateKeySecretRef.Name == "" {
			errs = append(errs, field.Required(path.Index(i).Child("privateKeySecretRef", "name"), ""))
		}
	}
	return errs
}
