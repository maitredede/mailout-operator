// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GatewayReference points at the MailoutGateway an account uses. It may live in
// another namespace — the operator's — which is why the gateway, not the
// account, decides whether the reference is allowed.
type GatewayReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Namespace defaults to the operator's namespace, where gateways live.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// AccountMiltersSpec adjusts the gateway's filter chain for this account.
// Filters can only be switched off, never added: an account must not be able to
// route its mail through a filter of its choosing.
type AccountMiltersSpec struct {
	// Disable names gateway filters to skip for this account, by their
	// spec.milters[].name.
	// +optional
	Disable []string `json:"disable,omitempty"`
}

// MailoutAccountSpec is one application's SMTP credentials. The operator
// generates the password, writes it to a Secret in this namespace, and keeps
// only its bcrypt hash — nothing but that Secret ever holds the cleartext.
type MailoutAccountSpec struct {
	GatewayRef GatewayReference `json:"gatewayRef"`

	// Username defaults to <namespace>.<name>. It must be unique across the
	// gateway; the webhook rejects a collision.
	//
	// The character set is deliberately narrow. This name is interpolated into
	// the Received header of every message the account sends, so a CR or LF in
	// it would end the header block and let the account write headers — and a
	// body — of its own choosing. It is also part of every rate limiting key.
	// The pattern is what makes that impossible rather than merely unlikely; the
	// dataplane refuses the account as well, since a rendered configuration is
	// not the only way to feed it.
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([a-zA-Z0-9._@+-]{0,126}[a-zA-Z0-9])?$`
	// +optional
	Username string `json:"username,omitempty"`

	// SecretRef names the Secret the operator creates and owns in this
	// namespace. It is of type kubernetes.io/basic-auth and also carries host,
	// port and tls, so it can be mounted straight into the application's
	// environment.
	SecretRef LocalObjectReference `json:"secretRef"`

	// Rotation is an opaque value: changing it regenerates the password. Any
	// string works — a date, a ticket number, a counter.
	// +optional
	Rotation string `json:"rotation,omitempty"`

	// AllowedSenders lists the addresses this account may send from, either as
	// an exact address (app@example.com) or as a whole domain (*@example.com).
	//
	// Empty places no restriction on the envelope — and disables DKIM signing
	// for this account entirely. Declaring a sender is what earns a signature:
	// a signature vouches for a domain, and an account must not be able to
	// vouch for a domain it may not send from. This is also what stops one
	// tenant from having another tenant's domain signed.
	// +optional
	AllowedSenders []string `json:"allowedSenders,omitempty"`

	// EnforceHeaderFrom also applies allowedSenders to the message's From
	// header, not just to the envelope. On by default: an account that passes
	// the envelope check but forges its From header still shows a forged sender
	// to the recipient, whether or not DMARC alignment catches it.
	//
	// Turn it off for an application that legitimately sends on behalf of
	// arbitrary addresses — a ticketing system relaying a customer's reply, for
	// instance.
	// +kubebuilder:default=true
	// +optional
	EnforceHeaderFrom *bool `json:"enforceHeaderFrom,omitempty"`

	// +optional
	Milters AccountMiltersSpec `json:"milters,omitempty"`

	// Disabled keeps the account and its Secret but refuses authentication.
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// MailoutAccountStatus is the observed state.
type MailoutAccountStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Username is the name actually provisioned, defaults included.
	// +optional
	Username string `json:"username,omitempty"`

	// SecretName is the Secret holding the credentials.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// Gateway is the resolved gateway, as namespace/name.
	// +optional
	Gateway string `json:"gateway,omitempty"`

	// RotationObserved is the spec.rotation value the current password was
	// generated for.
	// +optional
	RotationObserved string `json:"rotationObserved,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=macct,categories=mailout
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.status.gateway`
// +kubebuilder:printcolumn:name="Username",type=string,JSONPath=`.status.username`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MailoutAccount is one application's account on a MailoutGateway.
type MailoutAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MailoutAccountSpec   `json:"spec,omitempty"`
	Status MailoutAccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MailoutAccountList is a list of MailoutAccount.
type MailoutAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailoutAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailoutAccount{}, &MailoutAccountList{})
}
