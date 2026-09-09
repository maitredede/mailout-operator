// Copyright (c) 2026 Damien Daly. All rights reserved.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	"github.com/maitredede/mailout-operator/internal/controller"
	monitoringv1 "github.com/maitredede/mailout-operator/internal/monitoring/v1"
	"github.com/maitredede/mailout-operator/internal/render"
	mailoutwebhook "github.com/maitredede/mailout-operator/internal/webhook/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
)

// operatorOptions are the manager's knobs.
type operatorOptions struct {
	metricsAddr      string
	maxCachedSecrets int
	probeAddr        string
	leaderElect      bool
	namespace        string
	gatewayImage     string
	developmentLog   bool
	enableWebhooks   bool
	webhookPort      int
	webhookCertDir   string
}

func newOperatorCommand() *cobra.Command {
	opts := &operatorOptions{}
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the Kubernetes controller manager",
		Long: "Reconcile MailoutGateway and MailoutAccount objects into a running relay. " +
			"Gateways are only served in the operator's own namespace, which keeps upstream " +
			"credentials out of tenant namespaces.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOperator(cmd.Context(), opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.metricsAddr, "metrics-bind-address", "0", "metrics endpoint address; 0 disables it")
	f.StringVar(&opts.probeAddr, "health-probe-bind-address", ":8081", "health probe endpoint address")
	f.IntVar(&opts.maxCachedSecrets, "max-cached-secrets", 1024,
		"log an error when more Secrets than this carry the operator's label; 0 disables the check")
	f.BoolVar(&opts.leaderElect, "leader-elect", false,
		"elect a leader, so several replicas can run with only one reconciling")
	f.StringVar(&opts.namespace, "namespace", os.Getenv("POD_NAMESPACE"),
		"namespace holding the gateways; defaults to $POD_NAMESPACE")
	f.StringVar(&opts.gatewayImage, "gateway-image", os.Getenv("MAILOUT_GATEWAY_IMAGE"),
		"image running the dataplane; defaults to $MAILOUT_GATEWAY_IMAGE")
	f.BoolVar(&opts.developmentLog, "development-log", false, "human-readable, verbose logging")
	f.BoolVar(&opts.enableWebhooks, "enable-webhooks", true,
		"serve the validating webhooks; requires a certificate in --webhook-cert-dir")
	f.IntVar(&opts.webhookPort, "webhook-port", 9443, "webhook server port")
	f.StringVar(&opts.webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs",
		"directory holding tls.crt and tls.key for the webhook server")
	return cmd
}

func runOperator(ctx context.Context, opts *operatorOptions) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(opts.developmentLog)))
	log := ctrl.Log.WithName("setup")

	if opts.namespace == "" {
		return fmt.Errorf("--namespace is required (or set POD_NAMESPACE)")
	}
	if opts.gatewayImage == "" {
		return fmt.Errorf("--gateway-image is required (or set MAILOUT_GATEWAY_IMAGE)")
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))
	utilruntime.Must(monitoringv1.AddToScheme(scheme))

	restConfig := ctrl.GetConfigOrDie()

	certManagerAvailable, err := controller.CertManagerInstalled(restConfig)
	if err != nil {
		return fmt.Errorf("detect cert-manager: %w", err)
	}
	log.Info("cert-manager detection", "available", certManagerAvailable)

	prometheusOperatorAvailable, err := controller.PrometheusOperatorInstalled(restConfig)
	if err != nil {
		return fmt.Errorf("detect prometheus-operator: %w", err)
	}
	log.Info("prometheus-operator detection", "available", prometheusOperatorAvailable)

	options := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: opts.metricsAddr},
		HealthProbeBindAddress: opts.probeAddr,
		LeaderElection:         opts.leaderElect,
		LeaderElectionID:       "mailout-operator.mailout.daly.nc",
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// Accounts live anywhere, so their Secrets must be watched
				// cluster-wide — but only the ones we wrote. Caching every
				// Secret in the cluster would be both wasteful and a needless
				// widening of what the operator holds in memory. Secrets the
				// user brings (upstream credentials, certificates) are read
				// uncached through the APIReader instead.
				&corev1.Secret{}: {
					Label: labels.SelectorFromSet(labels.Set{
						"app.kubernetes.io/managed-by": "mailout-operator",
					}),
					Transform: keepOnlyCredentialKeys,
				},
			},
		},
	}
	if opts.enableWebhooks {
		options.WebhookServer = webhookserver.NewServer(webhookserver.Options{
			Port:    opts.webhookPort,
			CertDir: opts.webhookCertDir,
		})
	}

	mgr, err := ctrl.NewManager(restConfig, options)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := (&controller.GatewayReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		APIReader:            mgr.GetAPIReader(),
		OperatorNamespace:    opts.namespace,
		GatewayImage:         opts.gatewayImage,
		CertManagerAvailable: certManagerAvailable,

		PrometheusOperatorAvailable: prometheusOperatorAvailable,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up gateway controller: %w", err)
	}
	if err := (&controller.AccountReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: opts.namespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up account controller: %w", err)
	}

	if opts.enableWebhooks {
		if err := mailoutwebhook.SetupGatewayWebhookWithManager(mgr, opts.namespace, certManagerAvailable); err != nil {
			return fmt.Errorf("set up gateway webhook: %w", err)
		}
		if err := mailoutwebhook.SetupAccountWebhookWithManager(mgr, opts.namespace); err != nil {
			return fmt.Errorf("set up account webhook: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}

	if err := watchCachedSecretCount(mgr, opts.maxCachedSecrets); err != nil {
		return fmt.Errorf("add secret cache watch: %w", err)
	}

	log.Info("starting manager", "namespace", opts.namespace, "gatewayImage", opts.gatewayImage)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

// cachedSecretKeys are the only Secret keys the operator reads from its cache:
// the generated password, kept so a reconcile does not regenerate it, and its
// hash, which is what the gateway's configuration is built from.
var cachedSecretKeys = []string{corev1.BasicAuthPasswordKey, render.PasswordHashKey}

// keepOnlyCredentialKeys drops everything else from a Secret before it enters
// the cache.
//
// The cache selects on a label, and a label is something anyone can put on
// their own Secret. Six hundred labelled Secrets of a megabyte each would
// otherwise all be held in memory, against a 512Mi limit — the operator would
// OOMKill in a loop and nothing would reconcile for anyone. Keeping only the
// two keys we actually read makes that Secret cost a couple of hundred bytes
// whatever is written in it, so the problem does not need to be bounded: it
// does not exist.
//
// The Secrets a user brings — upstream credentials, certificates, DKIM keys —
// are not cached at all; they are read through the APIReader when needed.
func keepOnlyCredentialKeys(obj any) (any, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return obj, nil
	}
	trimmed := make(map[string][]byte, len(cachedSecretKeys))
	for _, key := range cachedSecretKeys {
		if value, ok := secret.Data[key]; ok {
			trimmed[key] = value
		}
	}
	secret.Data = trimmed
	// StringData is a write-only field on the API, but an object built locally
	// can carry it; there is no reason for it to reach the cache either.
	secret.StringData = nil
	return secret, nil
}

// watchCachedSecretCount logs when the number of labelled Secrets passes a
// threshold.
//
// The transform above means a flood no longer costs memory, so this is a
// signal rather than a defence: a count far above the number of accounts means
// someone is putting the operator's label on Secrets of their own, which is
// worth seeing even when it is harmless.
func watchCachedSecretCount(mgr ctrl.Manager, threshold int) error {
	if threshold <= 0 {
		return nil
	}
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		log := ctrl.Log.WithName("secret-cache")
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			var secrets corev1.SecretList
			if err := mgr.GetClient().List(ctx, &secrets); err != nil {
				log.Error(err, "cannot count cached secrets")
			} else if len(secrets.Items) > threshold {
				log.Error(nil, "more Secrets carry the operator's label than expected; "+
					"anyone can apply that label, so this may be someone else's doing",
					"count", len(secrets.Items), "threshold", threshold)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}))
}
