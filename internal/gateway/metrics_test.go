// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// counter reads one labelled counter back from the registry.
func counter(t *testing.T, gw *testGateway, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := gw.metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			if !hasLabels(m.GetLabel(), labels) {
				continue
			}
			switch {
			case m.Counter != nil:
				return m.Counter.GetValue()
			case m.Gauge != nil:
				return m.Gauge.GetValue()
			case m.Histogram != nil:
				return float64(m.Histogram.GetSampleCount())
			}
		}
	}
	return 0
}

func hasLabels(pairs []*dto.LabelPair, want map[string]string) bool {
	for name, value := range want {
		found := false
		for _, p := range pairs {
			if p.GetName() == name && p.GetValue() == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestRelayedMessageIsCounted(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	body := "Subject: hello\r\n\r\nbody\r\n"
	if err := c.SendMail("app@example.test", []string{"dest@example.test"}, strings.NewReader(body)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	if got := counter(t, gw, "mailout_messages_total",
		map[string]string{"account": testAccount, "result": ResultRelayed}); got != 1 {
		t.Errorf("relayed messages = %v, want 1", got)
	}
	if got := counter(t, gw, "mailout_message_bytes_total",
		map[string]string{"account": testAccount}); got < float64(len(body)) {
		t.Errorf("relayed bytes = %v, want at least %d", got, len(body))
	}
	if got := counter(t, gw, "mailout_upstream_delivery_seconds", nil); got != 1 {
		t.Errorf("upstream deliveries observed = %v, want 1", got)
	}
}

// An upstream that is refusing must show up as deferred, not as rejected: the
// difference is whether the operator is expected to do something about it.
func TestUpstreamFailureIsCountedAsDeferred(t *testing.T) {
	gw := newTestGateway(t)
	gw.upstream.reject(&smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      "try again",
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("expected the submission to fail")
	}

	if got := counter(t, gw, "mailout_messages_total",
		map[string]string{"account": testAccount, "result": ResultDeferred}); got != 1 {
		t.Errorf("deferred messages = %v, want 1", got)
	}
	if got := counter(t, gw, "mailout_messages_total",
		map[string]string{"account": testAccount, "result": ResultRejected}); got != 0 {
		t.Errorf("rejected messages = %v, want 0", got)
	}
	// The attempt is still timed: a slow failure is exactly what an operator
	// wants to see on the latency histogram.
	if got := counter(t, gw, "mailout_upstream_delivery_seconds", nil); got != 1 {
		t.Errorf("upstream deliveries observed = %v, want 1", got)
	}
}

func TestRefusedSenderIsCountedAsRejected(t *testing.T) {
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Accounts[0].AllowedSenders = []string{"*@example.test"}
	})
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.Mail("ceo@victim.test", nil); err == nil {
		t.Fatal("expected MAIL FROM to be refused")
	}

	if got := counter(t, gw, "mailout_messages_total",
		map[string]string{"account": testAccount, "result": ResultRejected}); got != 1 {
		t.Errorf("rejected messages = %v, want 1", got)
	}
}

// A metric label must never be something the caller chooses: an unknown
// username is reported under a single placeholder, so that failed logins on
// made-up names cannot grow the series count without bound.
func TestAuthFailureOnUnknownUserDoesNotCreateALabel(t *testing.T) {
	gw := newTestGateway(t)

	for _, username := range []string{"nobody-1", "nobody-2", "nobody-3"} {
		c := gw.dialSubmission(t)
		if err := c.Auth(sasl.NewPlainClient("", username, "whatever")); err == nil {
			t.Fatalf("AUTH as %s should have failed", username)
		}
		_ = c.Close()
	}
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, "wrong")); err == nil {
		t.Fatal("AUTH with a wrong password should have failed")
	}

	if got := counter(t, gw, "mailout_auth_failures_total",
		map[string]string{"account": unknownAccount}); got != 3 {
		t.Errorf("unknown-account auth failures = %v, want 3", got)
	}
	if got := counter(t, gw, "mailout_auth_failures_total",
		map[string]string{"account": testAccount}); got != 1 {
		t.Errorf("known-account auth failures = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(gw.metrics.authFailures); got != 2 {
		t.Errorf("auth failure series = %d, want 2 (the account and the placeholder)", got)
	}
}

// A reload that is refused must leave the gauges describing what is actually
// running, not what was asked for: the previous configuration stays in service,
// so anything else would have the metrics describe a relay that does not exist.
func TestConfigReloadIsCounted(t *testing.T) {
	gw := newTestGateway(t)

	if got := counter(t, gw, "mailout_config_reloads_total",
		map[string]string{"result": "success"}); got != 1 {
		t.Errorf("successful reloads = %v, want 1", got)
	}
	if got := counter(t, gw, "mailout_accounts", nil); got != 1 {
		t.Errorf("served accounts = %v, want 1", got)
	}

	// A configuration with two accounts, refused for something common to all of
	// them: neither the count of accounts nor anything else about it is served.
	refused := &Config{
		Hostname: "gateway.test",
		Accounts: []Account{
			{Username: "one", PasswordHash: mustHash(t, "pw")},
			{Username: "two", PasswordHash: mustHash(t, "pw")},
		},
	}
	if err := gw.srv.Reload(refused); err == nil {
		t.Fatal("a configuration with no listener was accepted")
	}

	if got := counter(t, gw, "mailout_config_reloads_total",
		map[string]string{"result": "failure"}); got != 1 {
		t.Errorf("failed reloads = %v, want 1", got)
	}
	if got := counter(t, gw, "mailout_config_reloads_total",
		map[string]string{"result": "success"}); got != 1 {
		t.Errorf("successful reloads = %v, want 1 after a refused reload", got)
	}
	// Still the one account of the running configuration, not the two that were
	// refused.
	if got := counter(t, gw, "mailout_accounts", nil); got != 1 {
		t.Errorf("served accounts = %v, want 1: the refused configuration is not the one in service", got)
	}
}

func TestServeMetricsExposesTheRegistry(t *testing.T) {
	m := NewMetrics()
	m.messageHandled("app1", ResultRelayed)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx := t.Context()
	done := make(chan error, 1)
	go func() { done <- ServeMetrics(ctx, addr, m, testLogger()) }()

	body := getWithRetry(t, "http://"+addr+"/metrics")
	if !strings.Contains(body, `mailout_messages_total{account="app1",result="relayed"} 1`) {
		t.Errorf("counter missing from the exposition:\n%s", body)
	}
	// The standard collectors are registered too, which is what makes the
	// endpoint useful for anything but message counts.
	if !strings.Contains(body, "go_goroutines") {
		t.Error("the Go collector is not registered")
	}
}

func TestServeMetricsDisabledByAnEmptyAddress(t *testing.T) {
	// Nothing to cancel: an empty address must return immediately rather than
	// block until shutdown.
	if err := ServeMetrics(context.Background(), "", NewMetrics(), testLogger()); err != nil {
		t.Fatalf("ServeMetrics with no address: %v", err)
	}
}

// getWithRetry polls until the server is accepting, then returns the body. The
// listener is opened by ServeMetrics itself, so there is a window where the
// port is not bound yet.
func getWithRetry(t *testing.T, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			return string(body)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("GET %s never succeeded: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The dashboard in config/grafana names metrics as strings, so nothing but a
// test connects it to the collectors. Renaming a metric would otherwise leave
// panels silently empty — the worst kind of monitoring failure, because an
// empty graph reads as "nothing is happening".
func TestGrafanaDashboardOnlyUsesMetricsWeExpose(t *testing.T) {
	const dashboard = "../../config/grafana/mailout.json"

	raw, err := os.ReadFile(dashboard)
	if err != nil {
		t.Fatalf("read %s: %v", dashboard, err)
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("%s is not valid JSON: %v", dashboard, err)
	}

	exposed := exposedMetricNames(t)
	seen := map[string]bool{}
	for _, name := range regexp.MustCompile(`mailout_[a-z_]+`).FindAllString(string(raw), -1) {
		// A histogram is queried through its derived series, which no registry
		// reports as a family of its own.
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
		if !exposed[base] {
			t.Errorf("dashboard queries %q, which the gateway does not expose", name)
		}
		seen[base] = true
	}
	for name := range exposed {
		if !seen[name] {
			t.Errorf("metric %q is exposed but appears on no panel", name)
		}
	}
}

// exposedMetricNames gathers every mailout metric after exercising each
// recorder once, since a counter that has never been incremented is not
// reported at all.
func exposedMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	m := NewMetrics()
	m.messageRelayed("account", 1)
	m.messageSpooled("account")
	m.authFailed("account")
	m.milterDecided("milter", decisionAccept)
	m.dkimResult("example.test", dkimSigned)
	m.rateLimitDecided("account", rateLimitAllowed)
	m.upstreamDelivered(time.Millisecond)
	m.configReloaded("success", 1, 0)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "mailout_") {
			names[family.GetName()] = true
		}
	}
	return names
}
