// Copyright (c) 2026 Damien Daly. All rights reserved.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MailoutGatewaySpec describes one relay: what it listens on, what it filters
// with, and where it sends. Only gateways in the operator's own namespace are
// served, which keeps the upstream credentials out of tenant namespaces.
type MailoutGatewaySpec struct {
	// Hostname is announced in the SMTP banner and used as the EHLO name when
	// relaying. Defaults to the gateway's name.
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// +optional
	Listeners ListenersSpec `json:"listeners,omitempty"`

	TLS GatewayTLSSpec `json:"tls"`

	Upstream UpstreamSpec `json:"upstream"`

	// DKIM keys used for every account of this gateway, unless the account
	// overrides them.
	// +optional
	DKIM []DKIMKeySpec `json:"dkim,omitempty"`

	// +optional
	Milters []MilterSpec `json:"milters,omitempty"`

	// AllowedAccounts controls which namespaces may attach accounts to this
	// gateway. The gateway's owner decides, not the account's.
	// +optional
	AllowedAccounts AllowedAccountsSpec `json:"allowedAccounts,omitempty"`

	// +optional
	Deployment DeploymentSpec `json:"deployment,omitempty"`
}

// ListenersSpec selects the sockets the gateway serves. Both listeners
// authenticate; neither ever carries a credential in clear, because AUTH is
// only offered once TLS is up.
type ListenersSpec struct {
	// Submission is the STARTTLS listener. Present by default on port 587.
	// +optional
	Submission *ListenerSpec `json:"submission,omitempty"`
	// SMTPS is the implicit-TLS listener. Absent unless declared.
	// +optional
	SMTPS *ListenerSpec `json:"smtps,omitempty"`
}

// ListenerSpec is one socket.
type ListenerSpec struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`
}

// GatewayTLSSpec is the certificates served to clients. Several certificates
// make the gateway answer on several names through SNI, on both listeners.
//
// Either bring your own Secrets with certificateRefs, or give an issuerRef and
// dnsNames and let the operator create the cert-manager Certificate.
type GatewayTLSSpec struct {
	// CertificateRefs are Secrets holding tls.crt and tls.key.
	// +optional
	CertificateRefs []LocalObjectReference `json:"certificateRefs,omitempty"`

	// IssuerRef, with DNSNames, makes the operator create and own a
	// cert-manager Certificate.
	// +optional
	IssuerRef *IssuerReference `json:"issuerRef,omitempty"`

	// DNSNames requested on the Certificate the operator creates.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// DefaultCertificate is the certificate served to a client that sends no
	// SNI. Names a certificateRefs entry; empty means the first one.
	// +optional
	DefaultCertificate string `json:"defaultCertificate,omitempty"`
}

// IssuerReference points at a cert-manager Issuer or ClusterIssuer.
type IssuerReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=Issuer;ClusterIssuer
	// +kubebuilder:default=Issuer
	// +optional
	Kind string `json:"kind,omitempty"`
	// +kubebuilder:default=cert-manager.io
	// +optional
	Group string `json:"group,omitempty"`
}

// UpstreamSpec is the SMTP server every accepted message is relayed to.
// Delivery is synchronous: the gateway answers 250 only once the upstream has
// accepted the message, so there is no spool to lose.
type UpstreamSpec struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=587
	// +optional
	Port int32 `json:"port,omitempty"`

	// +kubebuilder:default=StartTLS
	// +optional
	TLS TLSMode `json:"tls,omitempty"`

	// AuthSecretRef holds the credentials used towards the upstream, in the
	// username and password keys.
	// +optional
	AuthSecretRef *LocalObjectReference `json:"authSecretRef,omitempty"`

	// CASecretRef restricts upstream verification to this CA, read from the
	// ca.crt key.
	// +optional
	CASecretRef *SecretKeySelector `json:"caSecretRef,omitempty"`

	// InsecureSkipVerify disables upstream certificate verification. For
	// self-signed test upstreams only.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
}

// NamespacesFrom selects which namespaces may attach accounts.
// +kubebuilder:validation:Enum=All;Same;Selector
type NamespacesFrom string

const (
	// NamespacesFromAll accepts accounts from every namespace.
	NamespacesFromAll NamespacesFrom = "All"
	// NamespacesFromSame accepts only accounts in the gateway's namespace.
	NamespacesFromSame NamespacesFrom = "Same"
	// NamespacesFromSelector accepts accounts from namespaces matching
	// Selector.
	NamespacesFromSelector NamespacesFrom = "Selector"
)

// AllowedAccountsSpec follows the Gateway API's listener.allowedRoutes model:
// the gateway's owner grants access, rather than each consumer claiming it.
type AllowedAccountsSpec struct {
	// +kubebuilder:default=All
	// +optional
	Namespaces NamespacesFrom `json:"namespaces,omitempty"`
	// Selector applies when namespaces is Selector; it matches namespace
	// labels.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// DeploymentSpec shapes the pods the operator runs for this gateway.
type DeploymentSpec struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Image defaults to the operator's own image, so both halves stay in step.
	// +optional
	Image string `json:"image,omitempty"`

	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Enum=ClusterIP;LoadBalancer;NodePort
	// +kubebuilder:default=ClusterIP
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`

	// +optional
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`

	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
}

// ListenerStatus reports one serving socket.
type ListenerStatus struct {
	Name string `json:"name"`
	Port int32  `json:"port"`
	// Mode is starttls or implicit.
	Mode string `json:"mode"`
}

// MailoutGatewayStatus is the observed state.
type MailoutGatewayStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AcceptedAccounts is how many accounts this gateway currently serves.
	// +optional
	AcceptedAccounts int32 `json:"acceptedAccounts,omitempty"`

	// +optional
	Listeners []ListenerStatus `json:"listeners,omitempty"`

	// ServiceName is where applications point their SMTP client.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mgw;mailoutgw,categories=mailout
// +kubebuilder:printcolumn:name="Upstream",type=string,JSONPath=`.spec.upstream.host`
// +kubebuilder:printcolumn:name="Accounts",type=integer,JSONPath=`.status.acceptedAccounts`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MailoutGateway is one SMTP relay: its listeners, its filters and its target
// server.
type MailoutGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MailoutGatewaySpec   `json:"spec,omitempty"`
	Status MailoutGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MailoutGatewayList is a list of MailoutGateway.
type MailoutGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailoutGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailoutGateway{}, &MailoutGatewayList{})
}
