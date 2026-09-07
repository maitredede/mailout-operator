// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package v1 declares the minimum of cert-manager's API the operator writes:
// a Certificate with a secret name, DNS names and an issuer reference.
//
// Importing cert-manager's own module would pull in gateway-api and the whole
// ACME API surface for three fields that have not changed since v1. The API
// server validates what we send, so the risk of drift is limited to these
// fields.
// +kubebuilder:object:generate=true
// +groupName=cert-manager.io
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is cert-manager's API group and version.
var GroupVersion = schema.GroupVersion{Group: "cert-manager.io", Version: "v1"}

// SchemeBuilder registers the types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the types to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// IssuerReference points at an Issuer or ClusterIssuer.
type IssuerReference struct {
	Name string `json:"name"`
	// +optional
	Kind string `json:"kind,omitempty"`
	// +optional
	Group string `json:"group,omitempty"`
}

// CertificateSpec is the subset of cert-manager's CertificateSpec the operator
// sets. Unset fields keep cert-manager's own defaults.
type CertificateSpec struct {
	// SecretName is the Secret cert-manager fills with tls.crt and tls.key.
	SecretName string `json:"secretName"`
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`
	// +optional
	CommonName string          `json:"commonName,omitempty"`
	IssuerRef  IssuerReference `json:"issuerRef"`
}

// CertificateStatus is the part of the status the operator reads.
type CertificateStatus struct {
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// Certificate is a cert-manager Certificate.
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CertificateList is a list of Certificate.
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
