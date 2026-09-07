// Copyright (c) 2026 Damien Daly. All rights reserved.

// Package controller reconciles the mailout API objects into a running relay.
package controller

import (
	"context"
	"fmt"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GatewayNamespaceFor resolves which namespace an account's gatewayRef points
// at: its own namespace field, or the operator's, where gateways live.
func GatewayNamespaceFor(account *v1alpha1.MailoutAccount, operatorNamespace string) string {
	if account.Spec.GatewayRef.Namespace != "" {
		return account.Spec.GatewayRef.Namespace
	}
	return operatorNamespace
}

// namespaceAllowed reports whether a gateway accepts accounts from a namespace.
// The decision belongs to the gateway's owner, following the Gateway API's
// allowedRoutes model — an account cannot grant itself access.
func namespaceAllowed(ctx context.Context, c client.Client, gw *v1alpha1.MailoutGateway, namespace string) (bool, error) {
	from := gw.Spec.AllowedAccounts.Namespaces
	if from == "" {
		from = v1alpha1.NamespacesFromAll
	}
	switch from {
	case v1alpha1.NamespacesFromAll:
		return true, nil
	case v1alpha1.NamespacesFromSame:
		return namespace == gw.Namespace, nil
	case v1alpha1.NamespacesFromSelector:
		if gw.Spec.AllowedAccounts.Selector == nil {
			return false, nil
		}
		selector, err := metav1.LabelSelectorAsSelector(gw.Spec.AllowedAccounts.Selector)
		if err != nil {
			return false, fmt.Errorf("invalid allowedAccounts selector: %w", err)
		}
		var ns corev1.Namespace
		if err := c.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil {
			return false, fmt.Errorf("get namespace %s: %w", namespace, err)
		}
		return selector.Matches(labels.Set(ns.Labels)), nil
	default:
		return false, fmt.Errorf("unknown allowedAccounts.namespaces value %q", from)
	}
}

// UsernameFor is the account name actually provisioned.
func UsernameFor(account *v1alpha1.MailoutAccount) string {
	if account.Spec.Username != "" {
		return account.Spec.Username
	}
	return account.Namespace + "." + account.Name
}
