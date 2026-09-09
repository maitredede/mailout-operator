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

// grantedSenders is the union of the gateway's sender grants that apply to a
// namespace.
//
// The gateway's owner decides who may send from what; a grant with no selector
// applies to every namespace the gateway accepts, which is what a single-tenant
// gateway wants and what a shared one must not use for a domain belonging to
// one tenant.
func grantedSenders(ctx context.Context, c client.Reader, gw *v1alpha1.MailoutGateway,
	namespace string, nsLabels *labels.Set) ([]string, error) {
	var granted []string
	for i, grant := range gw.Spec.AllowedSenders {
		if grant.NamespaceSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(grant.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("invalid allowedSenders[%d].namespaceSelector: %w", i, err)
			}
			if *nsLabels == nil {
				set, err := namespaceLabels(ctx, c, namespace)
				if err != nil {
					return nil, err
				}
				*nsLabels = set
			}
			if !selector.Matches(*nsLabels) {
				continue
			}
		}
		granted = append(granted, grant.Senders...)
	}
	return granted, nil
}

// namespaceLabels reads a namespace's labels, once per account rather than once
// per grant.
func namespaceLabels(ctx context.Context, c client.Reader, namespace string) (labels.Set, error) {
	var ns corev1.Namespace
	if err := c.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil {
		return nil, fmt.Errorf("get namespace %s: %w", namespace, err)
	}
	if ns.Labels == nil {
		// Distinguishable from "not looked up yet" by the caller, which checks
		// for nil: an empty map means looked up and unlabelled.
		return labels.Set{}, nil
	}
	return labels.Set(ns.Labels), nil
}

// GrantedSendersFor is grantedSenders for callers outside the reconcile loop —
// the admission webhook, which checks one account at a time.
func GrantedSendersFor(ctx context.Context, c client.Reader, gw *v1alpha1.MailoutGateway,
	namespace string) ([]string, error) {
	var nsLabels labels.Set
	return grantedSenders(ctx, c, gw, namespace, &nsLabels)
}
