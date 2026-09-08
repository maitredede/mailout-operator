// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package v1alpha1 validates the mailout API objects at admission time, so that
// a mistake is reported when it is made rather than discovered later in a
// status field.
package v1alpha1

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	"github.com/maitredede/mailout-operator/internal/render"
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
	errs = append(errs, validateRateLimit(gw.Spec.RateLimit, spec.Child("rateLimit"))...)

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
	if gw.Spec.Upstream.HandlesDKIM && len(gw.Spec.DKIM) > 0 {
		warnings = append(warnings, "spec.upstream.handlesDKIM is set, so the "+
			"spec.dkim keys are declared but not used: the upstream signs instead")
	}
	if rl := gw.Spec.RateLimit; rl != nil {
		if rl.MessagesPerMinute == nil && rl.RecipientsPerMinute == nil {
			warnings = append(warnings, "spec.rateLimit declares a store but no limit: "+
				"nothing is counted and nothing is enforced")
		} else {
			// Worth saying out loud at admission time, because it is the one
			// surprising consequence of the design: the store joins the list of
			// things that can stop mail.
			warnings = append(warnings, "spec.rateLimit is set: the gateway fails closed, so mail stops "+
				"with a 451 whenever the quota store is unreachable — deploy it with replicas")
		}
		if rl.Store.TLS != nil && rl.Store.TLS.InsecureSkipVerify {
			warnings = append(warnings, "spec.rateLimit.store.tls.insecureSkipVerify is set: the store "+
				"certificate is not verified, so the connection can be intercepted")
		}
		if rl.Store.MasterName == "" && len(rl.Store.Addresses) > 1 {
			warnings = append(warnings, "spec.rateLimit.store lists several addresses without a masterName, "+
				"so they are treated as a Redis Cluster; a primary with replicas behind Sentinel needs "+
				"masterName set, and the gateway logs which mode it deduced at startup")
		}
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

	if submission != nil && smtps != nil {
		if submissionPort, smtpsPort := listenerPort(submission, 587), listenerPort(smtps, 465); submissionPort == smtpsPort {
			errs = append(errs, field.Invalid(path.Child("smtps", "port"), smtpsPort,
				"the two listeners cannot share a port"))
		}
	}

	// The metrics endpoint is served by the same process, on a port that is not
	// configurable. A listener claiming it makes the two race for the bind, one
	// loses with EADDRINUSE and takes the process down with it — so the pod
	// crash-loops, and which of the two failed is not even deterministic.
	for _, listener := range []struct {
		name    string
		spec    *v1alpha1.ListenerSpec
		defPort int32
	}{
		{"submission", submission, 587},
		{"smtps", smtps, 465},
	} {
		if listener.spec == nil {
			continue
		}
		if port := listenerPort(listener.spec, listener.defPort); port == render.MetricsPort {
			errs = append(errs, field.Invalid(path.Child(listener.name, "port"), port,
				fmt.Sprintf("port %d is the gateway's own metrics port; the pod would fail to bind both", render.MetricsPort)))
		}
	}
	return errs
}

func listenerPort(spec *v1alpha1.ListenerSpec, def int32) int32 {
	if spec.Port == 0 {
		return def
	}
	return spec.Port
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

// validateAllowedSenders checks each entry is an exact address or a *@domain
// wildcard. A malformed entry is refused rather than ignored: silently dropping
// it would narrow the policy in a way the author did not ask for, and they would
// discover it as mail being refused.
func validateAllowedSenders(senders []string, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	seen := map[string]bool{}
	for i, entry := range senders {
		normalized := strings.ToLower(strings.TrimSpace(entry))
		if seen[normalized] {
			errs = append(errs, field.Duplicate(path.Index(i), entry))
		}
		seen[normalized] = true

		local, domain, found := strings.Cut(normalized, "@")
		switch {
		case !found:
			errs = append(errs, field.Invalid(path.Index(i), entry,
				"must be an address (app@example.com) or a domain (*@example.com)"))
		case local == "":
			errs = append(errs, field.Invalid(path.Index(i), entry,
				"missing the local part; use *@example.com for a whole domain"))
		case domain == "":
			errs = append(errs, field.Invalid(path.Index(i), entry, "missing the domain"))
		case strings.Contains(local, "*") && local != "*":
			errs = append(errs, field.Invalid(path.Index(i), entry,
				"a wildcard local part must be exactly *, partial matches are not supported"))
		case strings.Contains(domain, "*"):
			errs = append(errs, field.Invalid(path.Index(i), entry,
				"wildcards are not supported in the domain; list each domain"))
		}
	}
	return errs
}

// validateRateLimit checks what the CRD schema cannot: that the addresses look
// like host:port, and that a quota is not declared without somewhere to count.
func validateRateLimit(spec *v1alpha1.RateLimitSpec, path *field.Path) field.ErrorList {
	if spec == nil {
		return nil
	}
	var errs field.ErrorList
	store := path.Child("store")
	if len(spec.Store.Addresses) == 0 {
		errs = append(errs, field.Required(store.Child("addresses"),
			"at least one address is required; the store is referenced, never deployed by the operator"))
	}
	for i, addr := range spec.Store.Addresses {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			errs = append(errs, field.Invalid(store.Child("addresses").Index(i), addr,
				"must be host:port"))
			continue
		}
		if _, err := strconv.Atoi(port); err != nil {
			errs = append(errs, field.Invalid(store.Child("addresses").Index(i), addr,
				"the port must be a number"))
		}
	}
	if spec.Store.SentinelAuthSecretRef != nil && spec.Store.MasterName == "" {
		errs = append(errs, field.Invalid(store.Child("sentinelAuthSecretRef"),
			spec.Store.SentinelAuthSecretRef.Name,
			"only meaningful with masterName, which is what selects Sentinel"))
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
		// A declared set that omits From is not a weaker signature, it is no
		// signature at all: the signing library refuses outright, and the
		// gateway turns that into a 451 for every message of that domain.
		// Caught here, it costs one admission error instead of a mail outage
		// whose cause is a field nobody suspects.
		if len(k.HeaderKeys) > 0 && !containsFold(k.HeaderKeys, "From") {
			errs = append(errs, field.Invalid(path.Index(i).Child("headerKeys"), k.HeaderKeys,
				"the From header must be signed; a set that omits it makes every message fail with 451"))
		}
	}
	return errs
}

// containsFold reports whether values holds want, ignoring case.
func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
