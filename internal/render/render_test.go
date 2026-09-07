// Copyright (c) 2026 Damien Daly. All rights reserved.

package render

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/maitredede/mailout-operator/api/v1alpha1"
	"github.com/maitredede/mailout-operator/internal/gateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

func testGateway() *v1alpha1.MailoutGateway {
	return &v1alpha1.MailoutGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "mailout-system"},
		Spec: v1alpha1.MailoutGatewaySpec{
			Hostname: "mail.example.com",
			Listeners: v1alpha1.ListenersSpec{
				Submission: &v1alpha1.ListenerSpec{},
				SMTPS:      &v1alpha1.ListenerSpec{},
			},
			TLS: v1alpha1.GatewayTLSSpec{
				CertificateRefs: []v1alpha1.LocalObjectReference{{Name: "mail-tls"}},
			},
			Upstream: v1alpha1.UpstreamSpec{
				Host:    "smtp.provider.example",
				Port:    587,
				TLS:     v1alpha1.TLSModeStartTLS,
				Timeout: &metav1.Duration{Duration: 45 * time.Second},
			},
			DKIM: []v1alpha1.DKIMKeySpec{{
				Domain:              "example.com",
				Selector:            "mail",
				PrivateKeySecretRef: v1alpha1.SecretKeySelector{Name: "dkim-example"},
			}},
			Milters: []v1alpha1.MilterSpec{{
				Name:    "clamav",
				Address: "tcp://clamav-milter:7357",
				Timeout: &metav1.Duration{Duration: 30 * time.Second},
			}},
		},
	}
}

func TestGatewayConfig(t *testing.T) {
	cfg, err := GatewayConfig(Input{
		Gateway:          testGateway(),
		UpstreamUsername: "relay",
		UpstreamPassword: "hunter2",
		Accounts: []Account{
			{Username: "billing.invoicing", PasswordHash: "$2a$12$second"},
			{Username: "alpha.app", PasswordHash: "$2a$12$first"},
		},
	})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Fatalf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Listeners) != 2 ||
		cfg.Listeners[0].Addr != ":587" || cfg.Listeners[0].Mode != gateway.TLSModeSTARTTLS ||
		cfg.Listeners[1].Addr != ":465" || cfg.Listeners[1].Mode != gateway.TLSModeImplicit {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}
	if got := cfg.TLS.Certificates[0].CertFile; got != "/etc/mailout/tls/mail-tls/tls.crt" {
		t.Fatalf("certFile = %q", got)
	}
	if got := cfg.DKIM[0].PrivateKeyFile; got != "/etc/mailout/dkim/dkim-example/private.key" {
		t.Fatalf("dkim key path = %q", got)
	}
	if cfg.Upstream.Username != "relay" || cfg.Upstream.Password != "hunter2" {
		t.Fatalf("upstream credentials not carried: %+v", cfg.Upstream)
	}
	if cfg.Upstream.Timeout.D() != 45*time.Second {
		t.Fatalf("upstream timeout = %v", cfg.Upstream.Timeout.D())
	}
	// Accounts are sorted, so an unchanged set renders identical bytes.
	if cfg.Accounts[0].Username != "alpha.app" || cfg.Accounts[1].Username != "billing.invoicing" {
		t.Fatalf("accounts not sorted: %+v", cfg.Accounts)
	}
}

// The rendered configuration must be exactly what the dataplane accepts —
// otherwise the operator would happily publish a config that the gateway then
// refuses to start on.
func TestRenderedConfigIsValidForTheDataplane(t *testing.T) {
	cfg, err := GatewayConfig(Input{
		Gateway:  testGateway(),
		Accounts: []Account{{Username: "app", PasswordHash: "$2a$12$hash"}},
	})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Round-trip through YAML the way the gateway will read it, then validate.
	reparsed := &gateway.Config{}
	if err := yaml.UnmarshalStrict(raw, reparsed); err != nil {
		t.Fatalf("the rendered configuration does not parse back:\n%s\n%v", raw, err)
	}
	if err := reparsed.Validate(); err != nil {
		t.Fatalf("the rendered configuration is invalid:\n%s\n%v", raw, err)
	}
}

// Rendering must be deterministic: the operator compares rendered bytes to
// decide whether to update the Secret, so an unstable order would rewrite it
// forever.
func TestGatewayConfigIsDeterministic(t *testing.T) {
	in := Input{
		Gateway: testGateway(),
		Accounts: []Account{
			{Username: "c", PasswordHash: "3"},
			{Username: "a", PasswordHash: "1"},
			{Username: "b", PasswordHash: "2"},
		},
	}
	first, err := GatewayConfig(in)
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	// Reversing the input order must not change the output.
	in.Accounts[0], in.Accounts[2] = in.Accounts[2], in.Accounts[0]
	second, err := GatewayConfig(in)
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	firstRaw, _ := yaml.Marshal(first)
	secondRaw, _ := yaml.Marshal(second)
	if string(firstRaw) != string(secondRaw) {
		t.Fatalf("rendering is not deterministic:\n%s\n---\n%s", firstRaw, secondRaw)
	}
}

// An empty listeners block must still produce a usable submission listener.
func TestGatewayConfigDefaultsToSubmissionOnly(t *testing.T) {
	gw := testGateway()
	gw.Spec.Listeners = v1alpha1.ListenersSpec{}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Addr != ":587" {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}
}

// Declaring only smtps must not silently add a submission listener.
func TestGatewayConfigSMTPSOnly(t *testing.T) {
	gw := testGateway()
	gw.Spec.Listeners = v1alpha1.ListenersSpec{SMTPS: &v1alpha1.ListenerSpec{Port: 4650}}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Addr != ":4650" ||
		cfg.Listeners[0].Mode != gateway.TLSModeImplicit {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}
}

func TestCertificateSecretNamesFromIssuer(t *testing.T) {
	gw := testGateway()
	gw.Spec.TLS = v1alpha1.GatewayTLSSpec{
		IssuerRef: &v1alpha1.IssuerReference{Name: "letsencrypt", Kind: "ClusterIssuer"},
		DNSNames:  []string{"mail.example.com"},
	}
	names := CertificateSecretNames(gw)
	if len(names) != 1 || names[0] != "default-tls" {
		t.Fatalf("got %v, want [default-tls]", names)
	}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if got := cfg.TLS.Certificates[0].KeyFile; got != "/etc/mailout/tls/default-tls/tls.key" {
		t.Fatalf("keyFile = %q", got)
	}
}

// Only the gateway's own keys are mounted. Accounts used to be able to name a
// Secret here, which let a tenant mount any Secret of the operator's namespace
// into the gateway pod — and sign with it for somebody else's domain.
func TestDKIMSecretNamesComesOnlyFromTheGateway(t *testing.T) {
	names := DKIMSecretNames(testGateway(), []Account{
		{Username: "a", AllowedSenders: []string{"*@other.com"}},
	})
	if len(names) != 1 || names[0] != "dkim-example" {
		t.Fatalf("got %v, want [dkim-example]", names)
	}
}

// An account's declared senders must reach the dataplane, since they gate both
// the envelope and the signature.
func TestGatewayConfigCarriesTheSenderPolicy(t *testing.T) {
	cfg, err := GatewayConfig(Input{
		Gateway: testGateway(),
		Accounts: []Account{{
			Username:            "app",
			PasswordHash:        "$2a$12$x",
			AllowedSenders:      []string{"app@example.com", "*@mail.example.com"},
			SkipHeaderFromCheck: true,
		}},
	})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	account := cfg.Accounts[0]
	if len(account.AllowedSenders) != 2 || account.AllowedSenders[0] != "app@example.com" {
		t.Fatalf("allowedSenders = %v", account.AllowedSenders)
	}
	if !account.SkipHeaderFromCheck {
		t.Fatal("skipHeaderFromCheck was not carried through")
	}
}

func TestDefaultUsername(t *testing.T) {
	if got := DefaultUsername("billing", "invoicing"); got != "billing.invoicing" {
		t.Fatalf("got %q", got)
	}
}

func TestListenerStatuses(t *testing.T) {
	cfg, err := GatewayConfig(Input{Gateway: testGateway()})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	statuses := ListenerStatuses(cfg)
	if len(statuses) != 2 || statuses[0].Port != 587 || statuses[1].Port != 465 {
		t.Fatalf("statuses = %+v", statuses)
	}
	if statuses[0].Mode != "starttls" || statuses[1].Mode != "implicit" {
		t.Fatalf("statuses = %+v", statuses)
	}
}

func TestDeploymentMountsConfigCertificatesAndKeys(t *testing.T) {
	gw := testGateway()
	accounts := []Account{{Username: "app", AllowedSenders: []string{"*@example.com"}}}
	cfg, err := GatewayConfig(Input{Gateway: gw, Accounts: accounts})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	deploy := Deployment(gw, cfg, accounts, "ghcr.io/maitredede/mailout-operator:v1")

	container := deploy.Spec.Template.Spec.Containers[0]
	if container.Image != "ghcr.io/maitredede/mailout-operator:v1" {
		t.Fatalf("image = %q", container.Image)
	}
	mounted := map[string]bool{}
	for _, m := range container.VolumeMounts {
		mounted[m.MountPath] = true
		if !m.ReadOnly {
			t.Errorf("mount %s is writable", m.MountPath)
		}
	}
	for _, want := range []string{
		"/etc/mailout",
		"/etc/mailout/tls/mail-tls",
		"/etc/mailout/dkim/dkim-example",
	} {
		if !mounted[want] {
			t.Errorf("%s is not mounted; got %v", want, mounted)
		}
	}
	// Two listeners plus the metrics port.
	if len(container.Ports) != 3 {
		t.Fatalf("ports = %+v", container.Ports)
	}
	if got := *container.SecurityContext.ReadOnlyRootFilesystem; !got {
		t.Error("root filesystem should be read-only")
	}
	if got := *container.SecurityContext.RunAsNonRoot; !got {
		t.Error("container should run as non-root")
	}
}

// Adding an account must not restart the relay: accounts are reloaded from
// disk, and a rollout would drop live SMTP connections.
func TestRestartHashIgnoresAccountChanges(t *testing.T) {
	gw := testGateway()
	base, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	withAccount, err := GatewayConfig(Input{
		Gateway:  gw,
		Accounts: []Account{{Username: "new", PasswordHash: "$2a$12$x"}},
	})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if RestartHash(gw, base, nil) != RestartHash(gw, withAccount, []Account{{Username: "new"}}) {
		t.Fatal("adding an account changed the restart hash")
	}
}

// Changing a listener does require a restart: the socket cannot move under a
// running process.
func TestRestartHashChangesWithListeners(t *testing.T) {
	gw := testGateway()
	before, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	gw2 := testGateway()
	gw2.Spec.Listeners.Submission = &v1alpha1.ListenerSpec{Port: 2587}
	after, err := GatewayConfig(Input{Gateway: gw2})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if RestartHash(gw, before, nil) == RestartHash(gw2, after, nil) {
		t.Fatal("changing a listener port left the restart hash unchanged")
	}
}

func TestCertificateFromIssuerRef(t *testing.T) {
	gw := testGateway()
	gw.Spec.TLS = v1alpha1.GatewayTLSSpec{
		IssuerRef: &v1alpha1.IssuerReference{Name: "letsencrypt", Kind: "ClusterIssuer"},
		DNSNames:  []string{"mail.example.com", "smtp.example.com"},
	}
	cert := Certificate(gw)
	if cert == nil {
		t.Fatal("no Certificate rendered")
	}
	if cert.Spec.SecretName != "default-tls" {
		t.Fatalf("secretName = %q", cert.Spec.SecretName)
	}
	if cert.Spec.IssuerRef.Kind != "ClusterIssuer" || cert.Spec.IssuerRef.Group != "cert-manager.io" {
		t.Fatalf("issuerRef = %+v", cert.Spec.IssuerRef)
	}
	if len(cert.Spec.DNSNames) != 2 {
		t.Fatalf("dnsNames = %v", cert.Spec.DNSNames)
	}
}

// Bringing your own certificate Secrets means the operator owns no Certificate.
func TestNoCertificateWhenCertificateRefsAreGiven(t *testing.T) {
	if cert := Certificate(testGateway()); cert != nil {
		t.Fatalf("unexpected Certificate: %+v", cert)
	}
}

func TestAccountSecretShape(t *testing.T) {
	gw := testGateway()
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "invoicing", Namespace: "billing"},
		Spec: v1alpha1.MailoutAccountSpec{
			SecretRef: v1alpha1.LocalObjectReference{Name: "invoicing-smtp"},
		},
	}
	secret := AccountSecret(account, "billing.invoicing", "s3cret", "$2a$12$hash",
		GatewayEndpoint(gw, cfg), gw.Namespace)

	if secret.Type != "kubernetes.io/basic-auth" {
		t.Fatalf("type = %q", secret.Type)
	}
	want := map[string]string{
		"username":     "billing.invoicing",
		"password":     "s3cret",
		"passwordHash": "$2a$12$hash",
		"host":         "default.mailout-system.svc",
		"port":         "587",
		"tls":          "starttls",
	}
	for key, value := range want {
		if got := string(secret.Data[key]); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
}

// The endpoint must prefer submission, which is what every mail library
// defaults to.
func TestGatewayEndpointPrefersSubmission(t *testing.T) {
	gw := testGateway()
	gw.Spec.Listeners = v1alpha1.ListenersSpec{
		SMTPS:      &v1alpha1.ListenerSpec{},
		Submission: &v1alpha1.ListenerSpec{},
	}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	endpoint := GatewayEndpoint(gw, cfg)
	if endpoint.Port != 587 || endpoint.TLS != "starttls" {
		t.Fatalf("endpoint = %+v", endpoint)
	}
}

// A gateway serving only implicit TLS must advertise that port instead.
func TestGatewayEndpointFallsBackToSMTPS(t *testing.T) {
	gw := testGateway()
	gw.Spec.Listeners = v1alpha1.ListenersSpec{SMTPS: &v1alpha1.ListenerSpec{}}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	endpoint := GatewayEndpoint(gw, cfg)
	if endpoint.Port != 465 || endpoint.TLS != "implicit" {
		t.Fatalf("endpoint = %+v", endpoint)
	}
}

func TestServicePortsMatchListeners(t *testing.T) {
	gw := testGateway()
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	svc := Service(gw, cfg)
	if len(svc.Spec.Ports) != 2 || svc.Spec.Ports[0].Port != 587 || svc.Spec.Ports[1].Port != 465 {
		t.Fatalf("ports = %+v", svc.Spec.Ports)
	}
	if svc.Spec.Selector["app.kubernetes.io/instance"] != "default" {
		t.Fatalf("selector = %v", svc.Spec.Selector)
	}
}

// The mounted Secrets must be readable by the non-root process that runs the
// dataplane. Mounting them 0400 leaves them owned by root and unreadable, which
// only a real cluster reveals — hence this regression test.
func TestMountedSecretsAreReadableByTheDataplaneUser(t *testing.T) {
	gw := testGateway()
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	deploy := Deployment(gw, cfg, nil, "image:test")

	podSecurity := deploy.Spec.Template.Spec.SecurityContext
	if podSecurity == nil || podSecurity.FSGroup == nil {
		t.Fatal("the pod has no fsGroup, so the mounted Secrets stay owned by root")
	}
	fsGroup := *podSecurity.FSGroup
	if podSecurity.RunAsUser == nil || podSecurity.RunAsGroup == nil {
		t.Fatal("the pod does not pin its user and group")
	}
	if *podSecurity.RunAsGroup != fsGroup {
		t.Fatalf("runAsGroup %d does not match fsGroup %d, so group-readable files are still unreadable",
			*podSecurity.RunAsGroup, fsGroup)
	}

	for _, volume := range deploy.Spec.Template.Spec.Volumes {
		if volume.Secret == nil {
			continue
		}
		if volume.Secret.DefaultMode == nil {
			t.Errorf("volume %s has no defaultMode", volume.Name)
			continue
		}
		// Group-readable is the point; anything stricter locks the process out.
		if mode := *volume.Secret.DefaultMode; mode&0o040 == 0 {
			t.Errorf("volume %s is mounted %#o, which the dataplane user cannot read",
				volume.Name, mode)
		}
	}
}

// The account Secret must say which gateway it feeds. It belongs to the
// account, so the gateway controller gets no ownership event when it is
// rewritten — these labels are what lets a rotation reach the dataplane without
// waiting for the periodic resync.
func TestAccountSecretIsLabelledWithItsGateway(t *testing.T) {
	gw := testGateway()
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	account := &v1alpha1.MailoutAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "invoicing", Namespace: "billing"},
		Spec: v1alpha1.MailoutAccountSpec{
			GatewayRef: v1alpha1.GatewayReference{Name: "default"},
			SecretRef:  v1alpha1.LocalObjectReference{Name: "invoicing-smtp"},
		},
	}
	secret := AccountSecret(account, "billing.invoicing", "p", "h",
		GatewayEndpoint(gw, cfg), gw.Namespace)

	if got := secret.Labels[LabelGatewayName]; got != "default" {
		t.Errorf("%s = %q, want default", LabelGatewayName, got)
	}
	if got := secret.Labels[LabelGatewayNamespace]; got != "mailout-system" {
		t.Errorf("%s = %q, want mailout-system", LabelGatewayNamespace, got)
	}
	// The cache only holds Secrets carrying this label, so losing it would make
	// the watch silently blind.
	if got := secret.Labels["app.kubernetes.io/managed-by"]; got != "mailout-operator" {
		t.Errorf("managed-by = %q", got)
	}
}

// A sending service that signs for us must be left to it: two signatures would
// mean ours breaking as soon as the service rewrites the body, and a dkim=fail
// in the DMARC reports for nothing.
func TestUpstreamHandlingDKIMDisablesSigning(t *testing.T) {
	gw := testGateway()
	gw.Spec.Upstream.HandlesDKIM = true

	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if len(cfg.DKIM) != 0 {
		t.Fatalf("keys were rendered despite handlesDKIM: %+v", cfg.DKIM)
	}
	// The keys stay declared in the spec, so switching back is one boolean.
	if len(gw.Spec.DKIM) != 1 {
		t.Fatal("the spec should keep its keys")
	}
	// And the Secret is no longer mounted, since nothing reads it.
	deploy := Deployment(gw, cfg, nil, "image:test")
	for _, volume := range deploy.Spec.Template.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == "dkim-example" {
			t.Fatal("the DKIM Secret is still mounted although nothing signs")
		}
	}
}

// The metrics endpoint gets a Service of its own. Folding it into the SMTP one
// would publish the relay's counters wherever that Service is exposed — and it
// can be a LoadBalancer.
func TestMetricsServiceIsSeparateAndAlwaysClusterIP(t *testing.T) {
	gw := testGateway()
	gw.Spec.Deployment.ServiceType = corev1.ServiceTypeLoadBalancer

	svc := MetricsService(gw)
	if svc.Name == gw.Name {
		t.Fatalf("metrics Service shares the SMTP Service's name %q", svc.Name)
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("metrics Service type = %s, want ClusterIP", svc.Spec.Type)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Name != MetricsPortName {
		t.Fatalf("ports = %+v", svc.Spec.Ports)
	}

	// The ServiceMonitor must select the metrics Service and nothing else: the
	// SMTP Service carries the shared labels too, and scraping port 587 as if
	// it spoke HTTP would produce a permanently failing target.
	monitor := ServiceMonitor(gw)
	selector := labels.SelectorFromSet(monitor.Spec.Selector.MatchLabels)
	if !selector.Matches(labels.Set(svc.Labels)) {
		t.Errorf("the monitor does not select the metrics Service: %v vs %v",
			monitor.Spec.Selector.MatchLabels, svc.Labels)
	}
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	if smtp := Service(gw, cfg); selector.Matches(labels.Set(smtp.Labels)) {
		t.Errorf("the monitor also selects the SMTP Service: %v", smtp.Labels)
	}
	if got := monitor.Spec.NamespaceSelector.MatchNames; len(got) != 1 || got[0] != gw.Namespace {
		t.Errorf("namespaceSelector = %v, want [%s]", got, gw.Namespace)
	}
	if len(monitor.Spec.Endpoints) != 1 || monitor.Spec.Endpoints[0].Port != MetricsPortName {
		t.Fatalf("endpoints = %+v", monitor.Spec.Endpoints)
	}
}

// The scrape target is a named port: prometheus-operator resolves the endpoint
// against the Service's port names, so the container port, the Service port and
// the monitor must agree on one string.
func TestMetricsPortIsNamedConsistently(t *testing.T) {
	gw := testGateway()
	cfg, err := GatewayConfig(Input{Gateway: gw})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	container := Deployment(gw, cfg, nil, "img").Spec.Template.Spec.Containers[0]

	var found bool
	for _, p := range container.Ports {
		if p.Name == MetricsPortName {
			found = true
			if p.ContainerPort != MetricsPort {
				t.Errorf("container metrics port = %d, want %d", p.ContainerPort, MetricsPort)
			}
		}
	}
	if !found {
		t.Fatalf("no %s container port: %+v", MetricsPortName, container.Ports)
	}

	wantArg := fmt.Sprintf("--metrics-bind-address=:%d", MetricsPort)
	if !slices.Contains(container.Args, wantArg) {
		t.Errorf("args = %v, want it to contain %s", container.Args, wantArg)
	}

	target := MetricsService(gw).Spec.Ports[0].TargetPort
	if target.StrVal != MetricsPortName {
		t.Errorf("Service targetPort = %v, want the named port %s", target, MetricsPortName)
	}
}
