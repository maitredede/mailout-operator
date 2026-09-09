// Copyright (c) 2026 Damien Daly. All rights reserved.

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	monitoringv1 "github.com/maitredede/mailout-operator/internal/monitoring/v1"
	"github.com/maitredede/mailout-operator/internal/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
)

// resyncInterval brings the gateway back through reconciliation even when
// nothing watched changed. It is what picks up an edit to a Secret the operator
// does not own — the upstream credentials, a certificate brought from outside —
// since those are read uncached and therefore trigger no event.
const resyncInterval = 5 * time.Minute

// GatewayReconciler renders one gateway into a running Deployment: its
// configuration Secret, its Service, its certificate, and the accounts it
// serves.
type GatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// APIReader reads straight from the API server, bypassing the cache. Used
	// for Secrets the operator does not own and therefore does not cache.
	APIReader client.Reader
	// OperatorNamespace is the only namespace whose gateways are served, which
	// keeps upstream credentials out of tenant namespaces.
	OperatorNamespace string
	// GatewayImage runs the dataplane. Defaults to the operator's own image so
	// both halves stay in step.
	GatewayImage string
	// CertManagerAvailable is false when the cluster has no cert-manager CRDs;
	// a gateway asking for an issuer then reports the problem instead of
	// failing forever.
	CertManagerAvailable bool
	// PrometheusOperatorAvailable is false when the cluster has no
	// ServiceMonitor CRD. The gateway still serves its metrics; only the scrape
	// declaration is skipped.
	PrometheusOperatorAvailable bool
}

// +kubebuilder:rbac:groups=mailout.daly.nc,resources=mailoutgateways,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mailout.daly.nc,resources=mailoutgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

// Reconcile brings one gateway to its desired state.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var gw v1alpha1.MailoutGateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if gw.Namespace != r.OperatorNamespace {
		// Serving a gateway from a tenant namespace would put its upstream
		// credentials within that tenant's reach.
		return ctrl.Result{}, r.markFailed(ctx, &gw, v1alpha1.ReasonInvalidSpec,
			fmt.Sprintf("gateways are only served in the operator namespace (%s)", r.OperatorNamespace))
	}

	accounts, err := r.collectAccounts(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	input := render.Input{Gateway: &gw, Accounts: accounts}
	if err := r.resolveSecrets(ctx, &gw, &input); err != nil {
		return ctrl.Result{}, r.markFailed(ctx, &gw, v1alpha1.ReasonSecretMissing, err.Error())
	}

	cfg, err := render.GatewayConfig(input)
	if err != nil {
		return ctrl.Result{}, r.markFailed(ctx, &gw, v1alpha1.ReasonInvalidSpec, err.Error())
	}
	if err := cfg.Validate(); err != nil {
		// Publishing a configuration the dataplane would refuse to start on
		// would take the relay down on the next rollout.
		return ctrl.Result{}, r.markFailed(ctx, &gw, v1alpha1.ReasonInvalidSpec, err.Error())
	}

	if err := r.reconcileCertificate(ctx, &gw); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileConfigSecret(ctx, &gw, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileService(ctx, &gw, cfg); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileMetrics(ctx, &gw, cfg); err != nil {
		return ctrl.Result{}, err
	}
	deployment, err := r.reconcileDeployment(ctx, &gw, cfg, accounts)
	if err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("gateway reconciled", "accounts", len(accounts), "listeners", len(cfg.Listeners))
	if err := r.updateStatus(ctx, &gw, cfg, accounts, deployment); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: resyncInterval}, nil
}

// collectAccounts returns the accounts this gateway serves, with the hash read
// from each one's own Secret. An account whose Secret is not written yet is
// skipped: it will come back when its own controller has provisioned it.
func (r *GatewayReconciler) collectAccounts(ctx context.Context, gw *v1alpha1.MailoutGateway) ([]render.Account, error) {
	log := logf.FromContext(ctx)

	var list v1alpha1.MailoutAccountList
	if err := r.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	var accounts []render.Account
	for i := range list.Items {
		account := &list.Items[i]
		if GatewayNamespaceFor(account, r.OperatorNamespace) != gw.Namespace ||
			account.Spec.GatewayRef.Name != gw.Name {
			continue
		}
		allowed, err := namespaceAllowed(ctx, r.Client, gw, account.Namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}

		var secret corev1.Secret
		key := client.ObjectKey{Namespace: account.Namespace, Name: account.Spec.SecretRef.Name}
		if err := r.Get(ctx, key, &secret); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("get secret %s: %w", key, err)
			}
			log.V(1).Info("account secret not provisioned yet, skipping",
				"account", account.Namespace+"/"+account.Name)
			continue
		}
		hash := string(secret.Data[render.PasswordHashKey])
		if hash == "" {
			log.V(1).Info("account secret carries no hash yet, skipping",
				"account", account.Namespace+"/"+account.Name)
			continue
		}

		// The effective policy is resolved here, so the dataplane receives a
		// list and never has to know about namespaces or selectors. What the
		// account asked for can only narrow what its namespace was granted.
		var nsLabels labels.Set
		granted, err := grantedSenders(ctx, r.Client, gw, account.Namespace, &nsLabels)
		if err != nil {
			return nil, err
		}
		senders, refused := gateway.GrantedSubset(granted, account.Spec.AllowedSenders)
		if len(refused) > 0 {
			// The webhook refuses this at admission; reaching here means the
			// grant was narrowed after the account was admitted, or the webhook
			// was bypassed. Dropping the entries is right — the gateway's owner
			// decides — but doing it silently would leave an account whose
			// status says nothing and whose mail is refused.
			log.Info("account asks for senders its namespace was not granted; dropping them",
				"account", account.Namespace+"/"+account.Name, "refused", refused)
		}
		if len(senders) == 0 {
			log.Info("account has no sender granted, so it can send nothing",
				"account", account.Namespace+"/"+account.Name)
		}

		accounts = append(accounts, render.Account{
			Username:            UsernameFor(account),
			PasswordHash:        hash,
			Disabled:            account.Spec.Disabled,
			AllowedSenders:      senders,
			SkipHeaderFromCheck: account.Spec.EnforceHeaderFrom != nil && !*account.Spec.EnforceHeaderFrom,
		})
	}
	return accounts, nil
}

// resolveSecrets reads the credentials and CAs the gateway points at, for both
// the upstream and the quota store. These Secrets belong to the user, so they
// are read uncached — the operator caches only what it owns.
func (r *GatewayReconciler) resolveSecrets(ctx context.Context, gw *v1alpha1.MailoutGateway, input *render.Input) error {
	if ref := gw.Spec.Upstream.AuthSecretRef; ref != nil {
		var secret corev1.Secret
		key := client.ObjectKey{Namespace: gw.Namespace, Name: ref.Name}
		if err := r.APIReader.Get(ctx, key, &secret); err != nil {
			return fmt.Errorf("upstream auth Secret %s: %w", key, err)
		}
		input.UpstreamUsername = string(secret.Data[corev1.BasicAuthUsernameKey])
		input.UpstreamPassword = string(secret.Data[corev1.BasicAuthPasswordKey])
		if input.UpstreamUsername == "" {
			return fmt.Errorf("upstream auth Secret %s has no username key", key)
		}
	}
	if ref := gw.Spec.Upstream.CASecretRef; ref != nil {
		var secret corev1.Secret
		key := client.ObjectKey{Namespace: gw.Namespace, Name: ref.Name}
		if err := r.APIReader.Get(ctx, key, &secret); err != nil {
			return fmt.Errorf("upstream CA Secret %s: %w", key, err)
		}
		caKey := ref.Key
		if caKey == "" {
			caKey = "ca.crt"
		}
		input.UpstreamCAPEM = string(secret.Data[caKey])
		if input.UpstreamCAPEM == "" {
			return fmt.Errorf("upstream CA Secret %s has no %s key", key, caKey)
		}
	}
	return r.resolveRateLimitSecrets(ctx, gw, input)
}

// resolveRateLimitSecrets reads what the quota store needs. A missing Secret is
// an error rather than an empty credential: the relay fails closed on a store it
// cannot reach, so publishing a configuration that silently cannot authenticate
// would stop mail with a diagnosis pointing at the wrong place.
func (r *GatewayReconciler) resolveRateLimitSecrets(ctx context.Context, gw *v1alpha1.MailoutGateway, input *render.Input) error {
	if gw.Spec.RateLimit == nil {
		return nil
	}
	store := gw.Spec.RateLimit.Store

	read := func(ref *v1alpha1.LocalObjectReference, what string) (username, password string, err error) {
		if ref == nil {
			return "", "", nil
		}
		var secret corev1.Secret
		key := client.ObjectKey{Namespace: gw.Namespace, Name: ref.Name}
		if err := r.APIReader.Get(ctx, key, &secret); err != nil {
			return "", "", fmt.Errorf("%s Secret %s: %w", what, key, err)
		}
		password = string(secret.Data[corev1.BasicAuthPasswordKey])
		if password == "" {
			return "", "", fmt.Errorf("%s Secret %s has no %s key", what, key, corev1.BasicAuthPasswordKey)
		}
		// A store with requirepass and no ACL user has a password and nothing
		// else, which is the common case.
		return string(secret.Data[corev1.BasicAuthUsernameKey]), password, nil
	}

	var err error
	creds := &input.RateLimitStore
	if creds.Username, creds.Password, err = read(store.AuthSecretRef, "rate limit store auth"); err != nil {
		return err
	}
	if creds.SentinelUsername, creds.SentinelPassword, err =
		read(store.SentinelAuthSecretRef, "rate limit store sentinel auth"); err != nil {
		return err
	}

	if store.TLS != nil && store.TLS.CASecretRef != nil {
		ref := store.TLS.CASecretRef
		var secret corev1.Secret
		key := client.ObjectKey{Namespace: gw.Namespace, Name: ref.Name}
		if err := r.APIReader.Get(ctx, key, &secret); err != nil {
			return fmt.Errorf("rate limit store CA Secret %s: %w", key, err)
		}
		caKey := ref.Key
		if caKey == "" {
			caKey = "ca.crt"
		}
		creds.CAPEM = string(secret.Data[caKey])
		if creds.CAPEM == "" {
			return fmt.Errorf("rate limit store CA Secret %s has no %s key", key, caKey)
		}
	}
	return nil
}

func (r *GatewayReconciler) reconcileCertificate(ctx context.Context, gw *v1alpha1.MailoutGateway) error {
	desired := render.Certificate(gw)
	if desired == nil {
		return nil
	}
	if !r.CertManagerAvailable {
		return fmt.Errorf("spec.tls.issuerRef needs cert-manager, whose CRDs are not installed")
	}
	cert := &certmanagerv1.Certificate{}
	cert.Name = desired.Name
	cert.Namespace = desired.Namespace
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cert, func() error {
		cert.Labels = desired.Labels
		cert.Spec = desired.Spec
		return controllerutil.SetControllerReference(gw, cert, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile certificate: %w", err)
	}
	return nil
}

func (r *GatewayReconciler) reconcileConfigSecret(ctx context.Context, gw *v1alpha1.MailoutGateway, cfg *gateway.Config) error {
	log := logf.FromContext(ctx)
	// Enforced before the write, not discovered after it: a Secret over 1 MiB
	// is refused by the API server, which fails the whole reconciliation while
	// the previous configuration stays in service — so the relay keeps running
	// and no change ever applies again, revocation included.
	if dropped := render.FitAccounts(cfg, render.ConfigBudget); len(dropped) > 0 {
		log.Error(nil, "configuration too large, accounts dropped largest first",
			"gateway", gw.Name, "dropped", dropped, "budget", render.ConfigBudget)
	}

	rendered, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}
	desired := render.ConfigSecret(gw, rendered)

	secret := &corev1.Secret{}
	secret.Name = desired.Name
	secret.Namespace = desired.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Labels = desired.Labels
		secret.Type = desired.Type
		secret.Data = desired.Data
		return controllerutil.SetControllerReference(gw, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile configuration secret: %w", err)
	}
	return nil
}

func (r *GatewayReconciler) reconcileService(ctx context.Context, gw *v1alpha1.MailoutGateway, cfg *gateway.Config) error {
	desired := render.Service(gw, cfg)
	svc := &corev1.Service{}
	svc.Name = desired.Name
	svc.Namespace = desired.Namespace
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = desired.Labels
		svc.Annotations = desired.Annotations
		// ClusterIP is assigned by the API server; keep whatever it gave us.
		clusterIP := svc.Spec.ClusterIP
		svc.Spec.Selector = desired.Spec.Selector
		svc.Spec.Type = desired.Spec.Type
		svc.Spec.Ports = desired.Spec.Ports
		svc.Spec.ClusterIP = clusterIP
		return controllerutil.SetControllerReference(gw, svc, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile service: %w", err)
	}
	return nil
}

// reconcileMetrics keeps the Prometheus Service, and the ServiceMonitor when
// the cluster can act on one. A cluster without prometheus-operator still gets
// the Service: it costs nothing, and it is what any other scraper points at.
func (r *GatewayReconciler) reconcileMetrics(ctx context.Context, gw *v1alpha1.MailoutGateway,
	cfg *gateway.Config) error {
	desired := render.MetricsService(gw)
	svc := &corev1.Service{}
	svc.Name = desired.Name
	svc.Namespace = desired.Namespace
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = desired.Labels
		clusterIP := svc.Spec.ClusterIP
		svc.Spec.Selector = desired.Spec.Selector
		svc.Spec.Type = desired.Spec.Type
		svc.Spec.Ports = desired.Spec.Ports
		svc.Spec.ClusterIP = clusterIP
		return controllerutil.SetControllerReference(gw, svc, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile metrics service: %w", err)
	}

	if err := r.reconcileMetricsNetworkPolicy(ctx, gw, cfg); err != nil {
		return err
	}

	if !r.PrometheusOperatorAvailable {
		return nil
	}
	desiredMonitor := render.ServiceMonitor(gw)
	monitor := &monitoringv1.ServiceMonitor{}
	monitor.Name = desiredMonitor.Name
	monitor.Namespace = desiredMonitor.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, monitor, func() error {
		monitor.Labels = desiredMonitor.Labels
		monitor.Spec = desiredMonitor.Spec
		return controllerutil.SetControllerReference(gw, monitor, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile service monitor: %w", err)
	}
	return nil
}

// reconcileMetricsNetworkPolicy applies the policy when scrapers are declared,
// and removes it when they stop being. Removal matters: a policy left behind
// after the field is cleared would keep denying whatever it denied, and the
// admin who cleared the field would have no reason to look for it.
func (r *GatewayReconciler) reconcileMetricsNetworkPolicy(ctx context.Context,
	gw *v1alpha1.MailoutGateway, cfg *gateway.Config) error {
	desired := render.MetricsNetworkPolicy(gw, cfg)
	if desired == nil {
		stale := &networkingv1.NetworkPolicy{}
		stale.Name = render.MetricsNetworkPolicyName(gw.Name)
		stale.Namespace = gw.Namespace
		if err := r.Delete(ctx, stale); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("remove metrics network policy: %w", err)
		}
		return nil
	}

	policy := &networkingv1.NetworkPolicy{}
	policy.Name = desired.Name
	policy.Namespace = desired.Namespace
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, policy, func() error {
		policy.Labels = desired.Labels
		policy.Spec = desired.Spec
		return controllerutil.SetControllerReference(gw, policy, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile metrics network policy: %w", err)
	}
	return nil
}

func (r *GatewayReconciler) reconcileDeployment(ctx context.Context, gw *v1alpha1.MailoutGateway,
	cfg *gateway.Config, accounts []render.Account) (*appsv1.Deployment, error) {
	desired := render.Deployment(gw, cfg, accounts, r.gatewayImage(gw))

	deployment := &appsv1.Deployment{}
	deployment.Name = desired.Name
	deployment.Namespace = desired.Namespace
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		deployment.Labels = desired.Labels
		// The selector is immutable, so it is only ever set on creation.
		if deployment.Spec.Selector == nil {
			deployment.Spec.Selector = desired.Spec.Selector
		}
		deployment.Spec.Replicas = desired.Spec.Replicas
		deployment.Spec.Template = desired.Spec.Template
		return controllerutil.SetControllerReference(gw, deployment, r.Scheme)
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile deployment: %w", err)
	}
	return deployment, nil
}

func (r *GatewayReconciler) gatewayImage(gw *v1alpha1.MailoutGateway) string {
	if gw.Spec.Deployment.Image != "" {
		return gw.Spec.Deployment.Image
	}
	return r.GatewayImage
}

func (r *GatewayReconciler) updateStatus(ctx context.Context, gw *v1alpha1.MailoutGateway,
	cfg *gateway.Config, accounts []render.Account, deployment *appsv1.Deployment) error {
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ObservedGeneration = gw.Generation
	gw.Status.AcceptedAccounts = int32(len(accounts))
	gw.Status.Listeners = render.ListenerStatuses(cfg)
	gw.Status.ServiceName = gw.Name

	setCondition(&gw.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionTrue,
		v1alpha1.ReasonAccepted, "Gateway configuration is valid", gw.Generation)

	if deployment.Status.AvailableReplicas > 0 {
		setCondition(&gw.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionTrue,
			v1alpha1.ReasonReady,
			fmt.Sprintf("%d replica(s) available", deployment.Status.AvailableReplicas), gw.Generation)
	} else {
		setCondition(&gw.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse,
			v1alpha1.ReasonDeploymentNotReady, "Waiting for the gateway pods to become available", gw.Generation)
	}
	return r.Status().Patch(ctx, gw, patch)
}

func (r *GatewayReconciler) markFailed(ctx context.Context, gw *v1alpha1.MailoutGateway, reason, message string) error {
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ObservedGeneration = gw.Generation
	setCondition(&gw.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionFalse, reason, message, gw.Generation)
	setCondition(&gw.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse, reason, message, gw.Generation)
	return r.Status().Patch(ctx, gw, patch)
}

// SetupWithManager registers the controller. Accounts live in every namespace,
// so a change to any of them is mapped back to the gateway it belongs to.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.MailoutGateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&corev1.Secret{}).
		Watches(&v1alpha1.MailoutAccount{},
			handler.EnqueueRequestsFromMapFunc(r.gatewayForAccount)).
		// An account's Secret belongs to the account, not to the gateway, so
		// rewriting it produces no ownership event here. Without this watch a
		// rotated password would only reach the dataplane at the next resync.
		Watches(&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.gatewayForAccountSecret)).
		Named("mailoutgateway")
	if r.CertManagerAvailable {
		builder = builder.Owns(&certmanagerv1.Certificate{})
	}
	if r.PrometheusOperatorAvailable {
		builder = builder.Owns(&monitoringv1.ServiceMonitor{})
	}
	return builder.Complete(r)
}

// gatewayForAccountSecret maps an account's credentials Secret back to the
// gateway whose configuration embeds its hash.
func (r *GatewayReconciler) gatewayForAccountSecret(_ context.Context, obj client.Object) []reconcile.Request {
	labels := obj.GetLabels()
	name := labels[render.LabelGatewayName]
	if name == "" {
		return nil
	}
	namespace := labels[render.LabelGatewayNamespace]
	if namespace == "" {
		namespace = r.OperatorNamespace
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: namespace, Name: name}}}
}

// gatewayForAccount maps an account to the gateway that must be re-rendered.
func (r *GatewayReconciler) gatewayForAccount(_ context.Context, obj client.Object) []reconcile.Request {
	account, ok := obj.(*v1alpha1.MailoutAccount)
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{
		Namespace: GatewayNamespaceFor(account, r.OperatorNamespace),
		Name:      account.Spec.GatewayRef.Name,
	}}}
}
