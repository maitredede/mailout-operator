// Copyright (c) 2026 Damien Daly. All rights reserved.

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	certmanagerv1 "github.com/maitredede/mailout-operator/internal/certmanager/v1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
					Containers: []corev1.Container{{
						Name:  "gateway",
						Image: image,
						Args: []string{
							"gateway",
							"--config=" + ConfigFilePath(),
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
func AccountSecret(account *v1alpha1.MailoutAccount, username, password, passwordHash string, endpoint Endpoint) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      account.Spec.SecretRef.Name,
			Namespace: account.Namespace,
			Labels:    accountSecretLabels(account),
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

func accountSecretLabels(account *v1alpha1.MailoutAccount) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "mailout",
		"app.kubernetes.io/component":  "account",
		"app.kubernetes.io/managed-by": "mailout-operator",
		"mailout.daly.nc/account":      account.Name,
	}
}
