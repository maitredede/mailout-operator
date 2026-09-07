// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package render turns the API objects into the dataplane's own configuration
// and into the Kubernetes objects that carry it. Everything here is a pure
// function of its inputs: no API calls, no clock, no randomness — which is what
// makes the operator's behaviour testable without a cluster.
package render

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
)

// Mount points inside the gateway pod. Certificates and DKIM keys are mounted
// from their own Secrets rather than copied into the rendered configuration, so
// that a cert-manager renewal reaches the pod without the operator touching
// anything.
const (
	// ConfigDir holds the rendered gateway configuration.
	ConfigDir = "/etc/mailout"
	// ConfigFileName is the key of the rendered configuration, in its Secret
	// and on disk.
	ConfigFileName = "gateway.yaml"
	// TLSDir is the parent of one directory per certificate Secret.
	TLSDir = "/etc/mailout/tls"
	// DKIMDir is the parent of one directory per DKIM key Secret.
	DKIMDir = "/etc/mailout/dkim"

	// DefaultDKIMKeyName is the Secret key holding a DKIM private key when the
	// spec does not say.
	DefaultDKIMKeyName = "private.key"
)

// Default ports, matching the well-known submission ports.
const (
	DefaultSubmissionPort = 587
	DefaultSMTPSPort      = 465
)

// Account is one resolved account: the API object's intent plus the hash the
// operator computed for it.
type Account struct {
	Username     string
	PasswordHash string
	Disabled     bool
	// AllowedSenders are the addresses and domains this account may send from.
	// Empty leaves the envelope unrestricted and disables signing entirely.
	AllowedSenders []string
	// SkipHeaderFromCheck limits the sender policy to the envelope.
	SkipHeaderFromCheck bool
	// DisableMilters names gateway filters this account opts out of.
	DisableMilters []string
}

// Input is everything needed to render a gateway's configuration, already read
// from the API.
type Input struct {
	Gateway *v1alpha1.MailoutGateway
	// Accounts are the accepted accounts, in any order; the rendering sorts
	// them so that an unchanged set produces an identical file.
	Accounts []Account
	// UpstreamUsername and UpstreamPassword come from the upstream auth Secret.
	UpstreamUsername string
	UpstreamPassword string
	// UpstreamCAPEM comes from the upstream CA Secret.
	UpstreamCAPEM string
	// RateLimitStore holds what the operator read from the quota store's
	// Secrets. Credentials are resolved by the operator and embedded in the
	// rendered configuration, like the upstream's: the gateway pod holds no API
	// permission of its own.
	RateLimitStore RateLimitCredentials
}

// RateLimitCredentials is what the operator resolved for the quota store.
type RateLimitCredentials struct {
	Username string
	Password string
	// SentinelUsername and SentinelPassword authenticate to the Sentinels,
	// which usually have credentials of their own.
	SentinelUsername string
	SentinelPassword string
	CAPEM            string
}

// GatewayConfig renders the dataplane configuration. The result is
// deterministic: the same input always produces the same bytes, so the operator
// can compare and avoid pointless updates that would restart nothing but churn
// the API server.
func GatewayConfig(in Input) (*gateway.Config, error) {
	gw := in.Gateway
	if gw == nil {
		return nil, fmt.Errorf("gateway is required")
	}

	hostname := gw.Spec.Hostname
	if hostname == "" {
		hostname = gw.Name
	}

	cfg := &gateway.Config{
		Hostname:  hostname,
		Listeners: renderListeners(gw.Spec.Listeners),
		TLS:       renderTLS(gw),
		Upstream:  renderUpstream(gw.Spec.Upstream, in),
		Milters:   renderMilters(gw.Spec.Milters),
	}
	cfg.RateLimit = renderRateLimit(gw.Spec.RateLimit, in.RateLimitStore)
	// An upstream that signs for us must be left to it: two signatures would
	// mean ours breaking as soon as the service rewrites the body.
	if !gw.Spec.Upstream.HandlesDKIM {
		cfg.DKIM = renderDKIM(gw.Spec.DKIM)
	}

	accounts := append([]Account(nil), in.Accounts...)
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Username < accounts[j].Username })
	for _, acct := range accounts {
		cfg.Accounts = append(cfg.Accounts, gateway.Account{
			Username:            acct.Username,
			PasswordHash:        acct.PasswordHash,
			Disabled:            acct.Disabled,
			AllowedSenders:      acct.AllowedSenders,
			SkipHeaderFromCheck: acct.SkipHeaderFromCheck,
			DisableMilters:      acct.DisableMilters,
		})
	}
	return cfg, nil
}

// renderRateLimit turns the quota spec into the dataplane's own, with the
// credentials the operator resolved folded in.
func renderRateLimit(spec *v1alpha1.RateLimitSpec, creds RateLimitCredentials) *gateway.RateLimit {
	if spec == nil {
		return nil
	}
	out := &gateway.RateLimit{
		Store: gateway.RateLimitStore{
			Addresses:        append([]string(nil), spec.Store.Addresses...),
			MasterName:       spec.Store.MasterName,
			DB:               int(spec.Store.DB),
			Username:         creds.Username,
			Password:         creds.Password,
			SentinelUsername: creds.SentinelUsername,
			SentinelPassword: creds.SentinelPassword,
		},
	}
	if spec.Store.TLS != nil {
		out.Store.TLS = true
		out.Store.InsecureSkipVerify = spec.Store.TLS.InsecureSkipVerify
		out.Store.RootCAPEM = creds.CAPEM
	}
	if spec.Store.Timeout != nil {
		out.Store.Timeout = gateway.Duration(spec.Store.Timeout.Duration)
	}
	if spec.MessagesPerMinute != nil {
		out.MessagesPerMinute = int(*spec.MessagesPerMinute)
	}
	if spec.RecipientsPerMinute != nil {
		out.RecipientsPerMinute = int(*spec.RecipientsPerMinute)
	}
	return out
}

// renderListeners defaults to a lone submission listener, which is what a
// gateway with an empty spec should be.
func renderListeners(spec v1alpha1.ListenersSpec) []gateway.Listener {
	var listeners []gateway.Listener
	if spec.Submission != nil || spec.SMTPS == nil {
		port := int32(DefaultSubmissionPort)
		if spec.Submission != nil && spec.Submission.Port != 0 {
			port = spec.Submission.Port
		}
		listeners = append(listeners, gateway.Listener{
			Name: "submission",
			Addr: fmt.Sprintf(":%d", port),
			Mode: gateway.TLSModeSTARTTLS,
		})
	}
	if spec.SMTPS != nil {
		port := int32(DefaultSMTPSPort)
		if spec.SMTPS.Port != 0 {
			port = spec.SMTPS.Port
		}
		listeners = append(listeners, gateway.Listener{
			Name: "smtps",
			Addr: fmt.Sprintf(":%d", port),
			Mode: gateway.TLSModeImplicit,
		})
	}
	return listeners
}

// CertificateMountPath is where a certificate Secret is mounted.
func CertificateMountPath(secretName string) string {
	return filepath.Join(TLSDir, secretName)
}

// DKIMMountPath is where a DKIM key Secret is mounted.
func DKIMMountPath(secretName string) string {
	return filepath.Join(DKIMDir, secretName)
}

func renderTLS(gw *v1alpha1.MailoutGateway) gateway.TLSConfig {
	out := gateway.TLSConfig{DefaultCertificate: gw.Spec.TLS.DefaultCertificate}
	for _, ref := range CertificateSecretNames(gw) {
		dir := CertificateMountPath(ref)
		out.Certificates = append(out.Certificates, gateway.CertificateRef{
			Name:     ref,
			CertFile: filepath.Join(dir, "tls.crt"),
			KeyFile:  filepath.Join(dir, "tls.key"),
		})
	}
	return out
}

// CertificateSecretNames is the ordered list of Secrets serving this gateway's
// certificates: the explicit refs, or the one Secret filled by the Certificate
// the operator owns.
func CertificateSecretNames(gw *v1alpha1.MailoutGateway) []string {
	if len(gw.Spec.TLS.CertificateRefs) > 0 {
		names := make([]string, 0, len(gw.Spec.TLS.CertificateRefs))
		for _, ref := range gw.Spec.TLS.CertificateRefs {
			names = append(names, ref.Name)
		}
		return names
	}
	if gw.Spec.TLS.IssuerRef != nil {
		return []string{OwnedCertificateSecretName(gw.Name)}
	}
	return nil
}

// OwnedCertificateSecretName is where the operator's own Certificate lands.
func OwnedCertificateSecretName(gatewayName string) string {
	return gatewayName + "-tls"
}

func renderUpstream(spec v1alpha1.UpstreamSpec, in Input) gateway.Upstream {
	upstream := gateway.Upstream{
		Host:               spec.Host,
		Port:               int(spec.Port),
		TLS:                upstreamTLSMode(spec.TLS),
		InsecureSkipVerify: spec.InsecureSkipVerify,
		RootCAPEM:          in.UpstreamCAPEM,
		Username:           in.UpstreamUsername,
		Password:           in.UpstreamPassword,
	}
	if spec.Timeout != nil {
		upstream.Timeout = gateway.Duration(spec.Timeout.Duration)
	}
	return upstream
}

func upstreamTLSMode(mode v1alpha1.TLSMode) gateway.TLSMode {
	switch mode {
	case v1alpha1.TLSModeImplicit:
		return gateway.TLSModeImplicit
	case v1alpha1.TLSModeNone:
		return gateway.TLSModeNone
	default:
		return gateway.TLSModeSTARTTLS
	}
}

func renderMilters(specs []v1alpha1.MilterSpec) []gateway.Milter {
	var out []gateway.Milter
	for _, m := range specs {
		milter := gateway.Milter{
			Name:     m.Name,
			Address:  m.Address,
			FailOpen: m.FailOpen,
		}
		if m.Timeout != nil {
			milter.Timeout = gateway.Duration(m.Timeout.Duration)
		}
		out = append(out, milter)
	}
	return out
}

func renderDKIM(specs []v1alpha1.DKIMKeySpec) []gateway.DKIMKey {
	var out []gateway.DKIMKey
	for _, k := range specs {
		out = append(out, gateway.DKIMKey{
			Domain:         k.Domain,
			Selector:       k.Selector,
			PrivateKeyFile: filepath.Join(DKIMMountPath(k.PrivateKeySecretRef.Name), DKIMKeyName(k)),
			HeaderKeys:     k.HeaderKeys,
		})
	}
	return out
}

// DKIMKeyName is the Secret key holding the private key.
func DKIMKeyName(spec v1alpha1.DKIMKeySpec) string {
	if spec.PrivateKeySecretRef.Key != "" {
		return spec.PrivateKeySecretRef.Key
	}
	return DefaultDKIMKeyName
}

// DKIMSecretNames lists every Secret holding a key this gateway signs with,
// deduplicated and ordered.
//
// Only the gateway's own keys are considered. Accounts used to be able to name a
// Secret here, which let a tenant mount any Secret of the operator's namespace
// into the gateway pod — and sign for somebody else's domain with it.
func DKIMSecretNames(gw *v1alpha1.MailoutGateway, accounts []Account) []string {
	seen := map[string]bool{}
	var names []string
	add := func(specs []v1alpha1.DKIMKeySpec) {
		for _, k := range specs {
			name := k.PrivateKeySecretRef.Name
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	// Nothing is mounted when the upstream signs for us: a private key in a pod
	// that never reads it is exposure for nothing.
	if gw != nil && !gw.Spec.Upstream.HandlesDKIM {
		add(gw.Spec.DKIM)
	}
	sort.Strings(names)
	return names
}

// DefaultUsername is the account name provisioned when the spec leaves it
// empty. Namespace-qualified, so two teams cannot collide by accident.
func DefaultUsername(namespace, name string) string {
	return namespace + "." + name
}

// ConfigFilePath is where the rendered configuration is mounted.
func ConfigFilePath() string {
	return filepath.Join(ConfigDir, ConfigFileName)
}

// ListenerStatuses reports the rendered listeners for the resource status.
func ListenerStatuses(cfg *gateway.Config) []v1alpha1.ListenerStatus {
	var out []v1alpha1.ListenerStatus
	for _, l := range cfg.Listeners {
		port := 0
		if _, portStr, found := strings.Cut(l.Addr, ":"); found {
			_, _ = fmt.Sscan(portStr, &port)
		}
		out = append(out, v1alpha1.ListenerStatus{
			Name: l.Name,
			Port: int32(port),
			Mode: string(l.Mode),
		})
	}
	return out
}
