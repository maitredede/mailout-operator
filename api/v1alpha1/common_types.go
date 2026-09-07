// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Condition types shared by both kinds.
const (
	// ConditionAccepted is true once the resource is well-formed and its
	// references resolve. An account whose gateway is missing is not accepted.
	ConditionAccepted = "Accepted"
	// ConditionReady is true once the resource is actually serving: the gateway
	// has its Deployment available, the account is present in the gateway's
	// account store.
	ConditionReady = "Ready"
)

// Condition reasons.
const (
	ReasonAccepted            = "Accepted"
	ReasonGatewayNotFound     = "GatewayNotFound"
	ReasonNamespaceNotAllowed = "NamespaceNotAllowed"
	ReasonUsernameConflict    = "UsernameConflict"
	ReasonInvalidSpec         = "InvalidSpec"
	ReasonReconciling         = "Reconciling"
	ReasonSecretMissing       = "SecretMissing"
	ReasonDeploymentNotReady  = "DeploymentNotReady"
	ReasonReady               = "Ready"
	ReasonDisabled            = "Disabled"
)

// LocalObjectReference names an object in the same namespace.
type LocalObjectReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// SecretKeySelector names one key of a Secret in the same namespace.
type SecretKeySelector struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key defaults to the kind-specific key documented on each field.
	// +optional
	Key string `json:"key,omitempty"`
}

// TLSMode is how TLS is negotiated towards the upstream server.
// +kubebuilder:validation:Enum=StartTLS;Implicit;None
type TLSMode string

const (
	// TLSModeStartTLS upgrades a plaintext connection in-band.
	TLSModeStartTLS TLSMode = "StartTLS"
	// TLSModeImplicit wraps the connection in TLS from the first byte.
	TLSModeImplicit TLSMode = "Implicit"
	// TLSModeNone disables TLS. Only acceptable on a trusted network.
	TLSModeNone TLSMode = "None"
)

// DKIMKeySpec is one DKIM signing key. Mail is signed only when its sender
// domain matches one of these; anything else is relayed unsigned rather than
// signed under a domain the operator does not own.
type DKIMKeySpec struct {
	// Domain is the SDID, published in DNS as <selector>._domainkey.<domain>.
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
	// +kubebuilder:validation:MinLength=1
	Selector string `json:"selector"`
	// PrivateKeySecretRef holds an RSA or Ed25519 key in PEM form. Key defaults
	// to "private.key"; a Secret produced by cert-manager uses "tls.key".
	PrivateKeySecretRef SecretKeySelector `json:"privateKeySecretRef"`
	// HeaderKeys restricts which headers are signed. Empty uses the library
	// default, which is the right choice unless you know otherwise.
	// +optional
	HeaderKeys []string `json:"headerKeys,omitempty"`
}

// MilterSpec is one filter every message is passed through. Filters run in the
// declared order, each seeing the previous one's modifications.
type MilterSpec struct {
	// Name identifies the filter in logs, in status, and in an account's
	// milters.disable list.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Address is tcp://host:port or unix:///path/to/socket.
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`
	// FailOpen lets mail through when the filter is unreachable. Off by
	// default: a virus scanner that is down must not turn the relay into a
	// conduit for malware.
	// +optional
	FailOpen bool `json:"failOpen,omitempty"`
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
}
