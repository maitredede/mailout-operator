// Copyright (c) 2026 Damien Daly. All rights reserved.

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	networkingv1 "k8s.io/api/networking/v1"
	"net"
	"strconv"
	"strings"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	monitoringv1 "github.com/maitredede/mailout-operator/internal/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// Object name suffixes and annotations.
const (
	// ConfigSecretSuffix is appended to the gateway name for the Secret holding
	// the rendered configuration. It is a Secret, not a ConfigMap: it carries
	// the account hashes and the upstream password.
	ConfigSecretSuffix = "-config"
	// LabelGatewayName and LabelGatewayNamespace mark which gateway an object
	// belongs to, for objects the gateway controller does not own.
	LabelGatewayName      = "mailout.daly.nc/gateway"
	LabelGatewayNamespace = "mailout.daly.nc/gateway-namespace"

	// MetricsServiceSuffix is appended to the gateway name for the Service
	// carrying the Prometheus endpoint. It is a Service of its own rather than
	// another port on the SMTP one: that Service can be a LoadBalancer, and
	// putting the metrics on it would publish the relay's internals wherever it
	// is exposed.
	MetricsServiceSuffix = "-metrics"
	// LabelService distinguishes the gateway's Services from one another, so
	// the ServiceMonitor selects the metrics one and nothing else.
	LabelService = "mailout.daly.nc/service"

	// RestartHashAnnotation carries a digest of the parts of the configuration
	// a running gateway cannot pick up by itself. The rest — accounts, keys,
	// filters — is reloaded from disk without a restart.
	RestartHashAnnotation = "mailout.daly.nc/restart-hash"
)

// The dataplane runs as this user, the nonroot user of the distroless base
// image. It is set explicitly rather than inherited, because the mounted
// Secrets are made readable by exactly this uid and gid.
const (
	dataplaneUID = int64(65532)
	dataplaneGID = int64(65532)
	// secretFileMode leaves the mounted Secrets readable by their group only.
	// The kubelet sets that group from the pod's fsGroup, so this mode plus
	// fsGroup is what makes the files readable by a non-root process — mounting
	// them 0400 would leave them owned by root and unreadable, which is a
	// failure only a real cluster reveals.
	secretFileMode = int32(0o440)
)

// The Prometheus endpoint. The port is fixed rather than configurable: it is
// reached through the Service by name, so there is nothing to gain from moving
// it, and one more knob is one more thing that can disagree with the
// ServiceMonitor.
const (
	MetricsPortName = "metrics"

	// SpoolVolumeName is the writable volume holding message bodies in flight.
	SpoolVolumeName = "spool"
	// spoolSizeLimit backstops the emptyDir. maxConnections (64) times
	// maxMessageBytes (25 MiB) is about 1.6 GiB of bodies in flight at the very
	// worst, so this leaves headroom without pretending the volume is a queue.
	spoolSizeLimit = "2Gi"
	MetricsPort    = int32(9090)
	MetricsPath    = "/metrics"
)

// MetricsServiceName is the Service carrying the Prometheus endpoint.
func MetricsServiceName(gatewayName string) string { return gatewayName + MetricsServiceSuffix }

// ConfigSecretName is the Secret holding the rendered configuration.
func ConfigSecretName(gatewayName string) string { return gatewayName + ConfigSecretSuffix }

// Labels are the labels every object the operator owns carries.
func Labels(gatewayName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "mailout",
		"app.kubernetes.io/instance":   gatewayName,
		"app.kubernetes.io/component":  "gateway",
		"app.kubernetes.io/managed-by": "mailout-operator",
	}
}

// SelectorLabels are the subset that selects the gateway's pods. They must
// never change for an existing Deployment: the selector is immutable.
func SelectorLabels(gatewayName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "mailout",
		"app.kubernetes.io/instance":  gatewayName,
		"app.kubernetes.io/component": "gateway",
	}
}

// ConfigSecret is the Secret carrying the rendered configuration.
func ConfigSecret(gw *v1alpha1.MailoutGateway, rendered []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConfigSecretName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    Labels(gw.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{ConfigFileName: rendered},
	}
}

// Certificate is the cert-manager Certificate the operator owns when the
// gateway names an issuer instead of bringing its own Secrets.
func Certificate(gw *v1alpha1.MailoutGateway) *certmanagerv1.Certificate {
	if gw.Spec.TLS.IssuerRef == nil {
		return nil
	}
	kind := gw.Spec.TLS.IssuerRef.Kind
	if kind == "" {
		kind = "Issuer"
	}
	group := gw.Spec.TLS.IssuerRef.Group
	if group == "" {
		group = "cert-manager.io"
	}
	dnsNames := gw.Spec.TLS.DNSNames
	if len(dnsNames) == 0 && gw.Spec.Hostname != "" {
		dnsNames = []string{gw.Spec.Hostname}
	}
	return &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gw.Name,
			Namespace: gw.Namespace,
			Labels:    Labels(gw.Name),
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: OwnedCertificateSecretName(gw.Name),
			DNSNames:   dnsNames,
			IssuerRef: certmanagerv1.IssuerReference{
				Name:  gw.Spec.TLS.IssuerRef.Name,
				Kind:  kind,
				Group: group,
			},
		},
	}
}

// Service exposes the gateway's listeners. Applications point their SMTP client
// at its name.
func Service(gw *v1alpha1.MailoutGateway, cfg *gateway.Config) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        gw.Name,
			Namespace:   gw.Namespace,
			Labels:      Labels(gw.Name),
			Annotations: gw.Spec.Deployment.ServiceAnnotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: SelectorLabels(gw.Name),
			Type:     serviceType(gw),
		},
	}
	for _, l := range ListenerStatuses(cfg) {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:       l.Name,
			Port:       l.Port,
			TargetPort: intstr.FromInt32(l.Port),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	return svc
}

func serviceType(gw *v1alpha1.MailoutGateway) corev1.ServiceType {
	if gw.Spec.Deployment.ServiceType != "" {
		return gw.Spec.Deployment.ServiceType
	}
	return corev1.ServiceTypeClusterIP
}

// MetricsService exposes the dataplane's Prometheus endpoint. Always
// ClusterIP, whatever the SMTP Service is: metrics are for the cluster's own
// monitoring, never for anything outside it.
func MetricsService(gw *v1alpha1.MailoutGateway) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MetricsServiceName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    MetricsServiceLabels(gw.Name),
		},
		Spec: corev1.ServiceSpec{
			Selector: SelectorLabels(gw.Name),
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				Name:       MetricsPortName,
				Port:       MetricsPort,
				TargetPort: intstr.FromString(MetricsPortName),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

// MetricsServiceLabels mark the metrics Service, and are what the ServiceMonitor
// selects on.
func MetricsServiceLabels(gatewayName string) map[string]string {
	labels := Labels(gatewayName)
	labels[LabelService] = MetricsPortName
	return labels
}

// ServiceMonitor asks prometheus-operator to scrape the gateway. It is only
// rendered when the cluster actually serves the CRD; see
// controller.PrometheusOperatorInstalled.
//
// The scrape interval is left unset on purpose: the scraping Prometheus already
// has one, and an operator that imposes its own would silently override a
// cluster-wide decision it knows nothing about.
func ServiceMonitor(gw *v1alpha1.MailoutGateway) *monitoringv1.ServiceMonitor {
	return &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MetricsServiceName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    MetricsServiceLabels(gw.Name),
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{MatchLabels: MetricsServiceLabels(gw.Name)},
			// The Service lives in the gateway's namespace, which is the
			// operator's; naming it keeps the monitor from matching a Service
			// of the same shape somewhere else.
			NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{gw.Namespace}},
			Endpoints: []monitoringv1.Endpoint{{
				Port:   MetricsPortName,
				Path:   MetricsPath,
				Scheme: "http",
			}},
		},
	}
}

// Deployment runs the dataplane. The rendered configuration and every
// certificate and DKIM key are mounted, and the gateway reloads them from disk
// on change — so rotating a key or renewing a certificate does not restart a
// single pod.
func Deployment(gw *v1alpha1.MailoutGateway, cfg *gateway.Config, accounts []Account, image string) *appsv1.Deployment {
	listeners := ListenerStatuses(cfg)

	volumes := []corev1.Volume{{
		Name: "config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  ConfigSecretName(gw.Name),
				DefaultMode: ptr.To(secretFileMode),
			},
		},
	}}
	mounts := []corev1.VolumeMount{{Name: "config", MountPath: ConfigDir, ReadOnly: true}}

	// The only writable path in the container. Disk-backed on purpose: an
	// emptyDir with medium Memory is tmpfs, so it would count against the pod's
	// memory limit and bring back exactly the OOM the spool exists to avoid.
	//
	// sizeLimit is a backstop, not the bound that matters: exceeding it makes
	// the kubelet evict the pod, which is worse than refusing a message. What
	// actually bounds the disk is maxConnections times maxMessageBytes, and the
	// limit here leaves room above that.
	volumes = append(volumes, corev1.Volume{
		Name: SpoolVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				SizeLimit: ptr.To(resource.MustParse(spoolSizeLimit)),
			},
		},
	})
	mounts = append(mounts, corev1.VolumeMount{Name: SpoolVolumeName, MountPath: SpoolDir})

	for i, secretName := range CertificateSecretNames(gw) {
		name := fmt.Sprintf("tls-%d", i)
		volumes = append(volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  secretName,
					DefaultMode: ptr.To(secretFileMode),
				},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      name,
			MountPath: CertificateMountPath(secretName),
			ReadOnly:  true,
		})
	}
	for i, secretName := range DKIMSecretNames(gw, accounts) {
		name := fmt.Sprintf("dkim-%d", i)
		volumes = append(volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  secretName,
					DefaultMode: ptr.To(secretFileMode),
				},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      name,
			MountPath: DKIMMountPath(secretName),
			ReadOnly:  true,
		})
	}

	var ports []corev1.ContainerPort
	for _, l := range listeners {
		ports = append(ports, corev1.ContainerPort{
			Name:          l.Name,
			ContainerPort: l.Port,
			Protocol:      corev1.ProtocolTCP,
		})
	}
	ports = append(ports, corev1.ContainerPort{
		Name:          MetricsPortName,
		ContainerPort: MetricsPort,
		Protocol:      corev1.ProtocolTCP,
	})

	podAnnotations := map[string]string{RestartHashAnnotation: RestartHash(gw, cfg, accounts)}
	for k, v := range gw.Spec.Deployment.PodAnnotations {
		podAnnotations[k] = v
	}

	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(listeners[0].Port)},
		},
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gw.Name,
			Namespace: gw.Namespace,
			Labels:    Labels(gw.Name),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: gw.Spec.Deployment.Replicas,
			Selector: &metav1.LabelSelector{MatchLabels: SelectorLabels(gw.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      Labels(gw.Name),
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					// The dataplane never talks to the Kubernetes API: it reads a
					// file. Mounting the namespace's default ServiceAccount token
					// into the process that terminates untrusted SMTP and parses
					// attacker-supplied MIME hands out a cluster identity for
					// nothing — and a RoleBinding added to that default account
					// later would silently become the relay's.
					AutomountServiceAccountToken: ptr.To(false),
					Containers: []corev1.Container{{
						Name:            "gateway",
						Image:           image,
						ImagePullPolicy: PullPolicyFor(image),
						Args: []string{
							"gateway",
							"--config=" + ConfigFilePath(),
							fmt.Sprintf("--metrics-bind-address=:%d", MetricsPort),
							"--log-format=json",
						},
						Ports:          ports,
						VolumeMounts:   mounts,
						Resources:      gw.Spec.Deployment.Resources,
						ReadinessProbe: probe,
						LivenessProbe:  probe.DeepCopy(),
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							ReadOnlyRootFilesystem:   ptr.To(true),
							RunAsNonRoot:             ptr.To(true),
							RunAsUser:                ptr.To(dataplaneUID),
							RunAsGroup:               ptr.To(dataplaneGID),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes:      volumes,
					NodeSelector: gw.Spec.Deployment.NodeSelector,
					Tolerations:  gw.Spec.Deployment.Tolerations,
					Affinity:     gw.Spec.Deployment.Affinity,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(dataplaneUID),
						RunAsGroup:   ptr.To(dataplaneGID),
						// The kubelet applies this group to the mounted Secrets,
						// which is what lets a non-root process read them.
						FSGroup:        ptr.To(dataplaneGID),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				},
			},
		},
	}
}

// RestartHash digests only what a running gateway cannot pick up from disk:
// its sockets and its set of mounted Secrets. Accounts, keys and filters are
// deliberately excluded, so adding an account does not restart the relay and
// drop connections.
func RestartHash(gw *v1alpha1.MailoutGateway, cfg *gateway.Config, accounts []Account) string {
	var b strings.Builder
	for _, l := range cfg.Listeners {
		fmt.Fprintf(&b, "listener=%s:%s:%s\n", l.Name, l.Addr, l.Mode)
	}
	for _, name := range CertificateSecretNames(gw) {
		fmt.Fprintf(&b, "tls=%s\n", name)
	}
	for _, name := range DKIMSecretNames(gw, accounts) {
		fmt.Fprintf(&b, "dkim=%s\n", name)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// PasswordHashKey is where the account Secret keeps the bcrypt hash. The
// gateway's configuration is rendered from it, so the hash lives next to the
// cleartext it belongs to rather than being copied into a status field every
// reader of the API could see.
const PasswordHashKey = "passwordHash"

// AccountSecret is what an application consumes: a basic-auth Secret carrying
// the credentials and where to send. It is written entirely by the operator.
func AccountSecret(account *v1alpha1.MailoutAccount, username, password, passwordHash string,
	endpoint Endpoint, gatewayNamespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      account.Spec.SecretRef.Name,
			Namespace: account.Namespace,
			Labels:    accountSecretLabels(account, gatewayNamespace),
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			corev1.BasicAuthUsernameKey: []byte(username),
			corev1.BasicAuthPasswordKey: []byte(password),
			PasswordHashKey:             []byte(passwordHash),
			"host":                      []byte(endpoint.Host),
			"port":                      []byte(fmt.Sprint(endpoint.Port)),
			"tls":                       []byte(endpoint.TLS),
		},
	}
}

// Endpoint is where an application sends its mail.
type Endpoint struct {
	Host string
	Port int32
	// TLS is starttls or implicit, matching the listener the port belongs to.
	TLS string
}

// GatewayEndpoint is the in-cluster address of a gateway's preferred listener.
func GatewayEndpoint(gw *v1alpha1.MailoutGateway, cfg *gateway.Config) Endpoint {
	endpoint := Endpoint{
		Host: fmt.Sprintf("%s.%s.svc", gw.Name, gw.Namespace),
	}
	for _, l := range ListenerStatuses(cfg) {
		// Prefer submission: it is what every mail library defaults to.
		if endpoint.Port == 0 || l.Name == "submission" {
			endpoint.Port = l.Port
			endpoint.TLS = l.Mode
		}
	}
	return endpoint
}

func accountSecretLabels(account *v1alpha1.MailoutAccount, gatewayNamespace string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "mailout",
		"app.kubernetes.io/component":  "account",
		"app.kubernetes.io/managed-by": "mailout-operator",
		"mailout.daly.nc/account":      account.Name,
		// The gateway this account feeds. The Secret belongs to the account, so
		// the gateway controller gets no ownership event when it is rewritten;
		// these labels are how a rotation reaches the gateway without waiting
		// for the periodic resync.
		LabelGatewayName:      account.Spec.GatewayRef.Name,
		LabelGatewayNamespace: gatewayNamespace,
	}
}

// MetricsNetworkPolicyName is the policy restricting the metrics endpoint.
func MetricsNetworkPolicyName(gatewayName string) string { return gatewayName + "-metrics" }

// MetricsNetworkPolicy restricts the metrics port to the declared scrapers
// while leaving the SMTP listeners reachable from anywhere. It returns nil when
// no scraper is declared, because rendering a policy is not free: attaching one
// to a pod switches it to deny-by-default for ingress.
//
// The SMTP rule is what keeps this from being an outage. A policy naming only
// the metrics port would deny 587 and 465 along with everything else, and mail
// would stop for every tenant of the gateway — with nothing in the gateway's
// own logs to say why, because the connections never arrive.
func MetricsNetworkPolicy(gw *v1alpha1.MailoutGateway, cfg *gateway.Config) *networkingv1.NetworkPolicy {
	if len(gw.Spec.Metrics.AllowedScrapers) == 0 {
		return nil
	}

	tcp := corev1.ProtocolTCP
	var smtpPorts []networkingv1.NetworkPolicyPort
	for _, l := range cfg.Listeners {
		port := intstr.FromInt32(listenerPortOf(l))
		smtpPorts = append(smtpPorts, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port})
	}
	metricsPort := intstr.FromInt32(MetricsPort)

	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(gw.Spec.Metrics.AllowedScrapers))
	for _, scraper := range gw.Spec.Metrics.AllowedScrapers {
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: scraper.NamespaceSelector,
			PodSelector:       scraper.PodSelector,
		})
	}

	rules := []networkingv1.NetworkPolicyIngressRule{{
		// From is empty on purpose: every source. Submission comes from
		// applications anywhere in the cluster, and the relay authenticates
		// them rather than placing them.
		Ports: smtpPorts,
	}, {
		Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &metricsPort}},
		From:  peers,
	}}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MetricsNetworkPolicyName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    Labels(gw.Name),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: SelectorLabels(gw.Name)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     rules,
		},
	}
}

// listenerPortOf reads the port out of a rendered listener address.
func listenerPortOf(l gateway.Listener) int32 {
	_, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return int32(n) //nolint:gosec // a port fits in int32 by construction
}

// PullPolicyFor decides whether a node may serve this image from its cache.
//
// A moving tag served from cache is how two replicas end up running different
// code with nothing saying so, and how a rebuilt :dev never reaches the
// cluster. A digest or a version tag, on the other hand, means what it says, so
// pulling again on every start is a needless round trip to the registry.
func PullPolicyFor(image string) corev1.PullPolicy {
	if strings.Contains(image, "@sha256:") {
		return corev1.PullIfNotPresent
	}
	tag := ""
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		tag = image[i+1:]
	}
	switch tag {
	case "", "dev", "latest", "main", "edge", "nightly":
		return corev1.PullAlways
	default:
		return corev1.PullIfNotPresent
	}
}
