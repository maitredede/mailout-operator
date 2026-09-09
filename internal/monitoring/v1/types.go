// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package v1 declares the minimum of the prometheus-operator API the operator
// writes: a ServiceMonitor pointing at the gateway's metrics Service.
//
// Importing prometheus-operator's own module for four fields would pull its
// whole API surface — Prometheus, Alertmanager, ThanosRuler and their
// dependencies — into an operator that only ever creates this one object. The
// API server validates what we send, and these fields have been stable since
// the CRD was introduced.
// +kubebuilder:object:generate=true
// +groupName=monitoring.coreos.com
package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the prometheus-operator API group and version.
var GroupVersion = schema.GroupVersion{Group: "monitoring.coreos.com", Version: "v1"}

// SchemeBuilder registers the types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the types to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// Endpoint is one scrape target on the selected Service.
type Endpoint struct {
	// Port is the name of the Service port, not its number.
	// +optional
	Port string `json:"port,omitempty"`
	// +optional
	Path string `json:"path,omitempty"`
	// +optional
	Scheme string `json:"scheme,omitempty"`
	// Interval is a Prometheus duration such as 30s. Empty leaves the scraping
	// Prometheus' own default in place, which is the right answer unless the
	// gateway has a reason to differ.
	// +optional
	Interval string `json:"interval,omitempty"`
	// Authorization is the credential Prometheus presents. Only the safe form
	// is modelled: the secret is named, never inlined.
	// +optional
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
}

// SafeAuthorization is an Authorization header built from a Secret key.
type SafeAuthorization struct {
	// Type defaults to Bearer on the prometheus-operator side.
	// +optional
	Type string `json:"type,omitempty"`
	// +optional
	Credentials *corev1.SecretKeySelector `json:"credentials,omitempty"`
}

// NamespaceSelector restricts which namespaces the Service may live in.
type NamespaceSelector struct {
	// +optional
	Any bool `json:"any,omitempty"`
	// +optional
	MatchNames []string `json:"matchNames,omitempty"`
}

// ServiceMonitorSpec is the subset of the spec the operator sets.
type ServiceMonitorSpec struct {
	Selector metav1.LabelSelector `json:"selector"`
	// +optional
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`
	// +optional
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// JobLabel names the Service label whose value becomes the job label of
	// every scraped series.
	// +optional
	JobLabel string `json:"jobLabel,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceMonitor tells prometheus-operator to scrape a Service.
type ServiceMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceMonitorSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceMonitorList is a list of ServiceMonitor.
type ServiceMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceMonitor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceMonitor{}, &ServiceMonitorList{})
}
