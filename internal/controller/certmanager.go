// Copyright (c) 2026 Damien Daly. All rights reserved.

package controller

import (
	"fmt"

	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// CertManagerInstalled reports whether the cluster serves cert-manager's
// Certificate resource. Watching a kind that does not exist would keep the
// manager crash-looping, so a gateway asking for an issuer is told the truth
// instead.
func CertManagerInstalled(cfg *rest.Config) (bool, error) {
	client, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("discovery client: %w", err)
	}
	resources, err := client.ServerResourcesForGroupVersion(certmanagerv1.GroupVersion.String())
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) || apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, resource := range resources.APIResources {
		if resource.Kind == "Certificate" {
			return true, nil
		}
	}
	return false, nil
}
