// Copyright (c) 2026 Damien Daly. All rights reserved.

package controller

import (
	"fmt"

	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	monitoringv1 "github.com/maitredede/mailout-operator/internal/monitoring/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// CertManagerInstalled reports whether the cluster serves cert-manager's
// Certificate resource. Watching a kind that does not exist would keep the
// manager crash-looping, so a gateway asking for an issuer is told the truth
// instead.
func CertManagerInstalled(cfg *rest.Config) (bool, error) {
	return kindInstalled(cfg, certmanagerv1.GroupVersion, "Certificate")
}

// PrometheusOperatorInstalled reports whether the cluster serves ServiceMonitor.
// The gateway exposes its metrics either way; this only decides whether the
// operator also declares the scrape target, which is meaningless without
// prometheus-operator to act on it.
func PrometheusOperatorInstalled(cfg *rest.Config) (bool, error) {
	return kindInstalled(cfg, monitoringv1.GroupVersion, "ServiceMonitor")
}

// kindInstalled asks the API server whether a group/version serves a kind. A
// group that is absent entirely is not an error: it is the answer.
func kindInstalled(cfg *rest.Config, gv schema.GroupVersion, kind string) (bool, error) {
	client, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("discovery client: %w", err)
	}
	resources, err := client.ServerResourcesForGroupVersion(gv.String())
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) || apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, resource := range resources.APIResources {
		if resource.Kind == kind {
			return true, nil
		}
	}
	return false, nil
}
