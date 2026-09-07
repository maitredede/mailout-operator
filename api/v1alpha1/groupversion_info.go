// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package v1alpha1 holds the mailout API types: MailoutGateway, which describes
// one relay and where it sends, and MailoutAccount, which is one application's
// credentials on such a relay.
// +kubebuilder:object:generate=true
// +groupName=mailout.daly.nc
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the API group and version of these types.
var GroupVersion = schema.GroupVersion{Group: "mailout.daly.nc", Version: "v1alpha1"}

// SchemeBuilder registers the types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the types to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme
