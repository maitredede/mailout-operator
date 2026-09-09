// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Message outcomes, used as the result label of mailout_messages_total. The set
// is closed on purpose: a label whose values grow with traffic is how a metrics
// endpoint becomes the thing that takes the process down.
const (
	// ResultRelayed is a message the upstream accepted.
	ResultRelayed = "relayed"
	// ResultRejected is a permanent refusal — sender policy or a filter's
	// verdict. The client must not retry.
	ResultRejected = "rejected"
	// ResultDiscarded is a message a filter swallowed: accepted towards the
	// client, delivered nowhere.
	ResultDiscarded = "discarded"
	// ResultDeferred is a temporary failure — the upstream is unreachable,
	// signing failed. The client is expected to try again, so this is the one
	// to alert on.
	ResultDeferred = "deferred"
)

// Milter verdicts, used as the decision label.
const (
	decisionAccept      = "accept"
	decisionReject      = "reject"
	decisionDiscard     = "discard"
	decisionUnavailable = "unavailable"
)

// Rate limiting outcomes, used as the decision label.
const (
	rateLimitAllowed = "allowed"
	rateLimitDenied  = "denied"
	// rateLimitError is the fail-closed case: the store could not be reached
	// and the message was refused because of it. It is the series to alert on —
	// it means the quota store, not the tenant, is stopping mail.
	rateLimitError = "error"
)

// DKIM outcomes, used as the result label.
const (
	dkimSigned  = "signed"
	dkimRefused = "refused"
	dkimFailed  = "failed"
)

// unknownAccount labels what cannot be attributed to a configured account.
// Authentication failures carry a username chosen by whoever is connecting, so
// using it as a label would let anyone create an unbounded number of time
// series by guessing names. Only usernames that actually exist are reported.
const unknownAccount = "<unknown>"

// Metrics is the dataplane's instrumentation. It owns its registry rather than
// using the default one, so that nothing an imported package registers by
// accident ends up on the relay's endpoint.
//
// Every label here is bounded by configuration, never by traffic: the account
// is one of the gateway's own, the milter one of its filters, the domain one of
// its keys. No address, no recipient, no remote host.
type Metrics struct {
	registry *prometheus.Registry

	messages         *prometheus.CounterVec
	messagesSpooled  *prometheus.CounterVec
	messageBytes     *prometheus.CounterVec
	authFailures     *prometheus.CounterVec
	milterDecisions  *prometheus.CounterVec
	dkimSignatures   *prometheus.CounterVec
	rateLimit        *prometheus.CounterVec
	upstreamDelivery prometheus.Histogram
	configReloads    *prometheus.CounterVec
	accounts         prometheus.Gauge
	accountsRejected prometheus.Gauge
}

// NewMetrics builds the collectors on a fresh registry, along with the standard
// Go and process collectors.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_messages_total",
			Help: "Messages handled, by account and outcome.",
		}, []string{"account", "result"}),
		messagesSpooled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_messages_spooled_total",
			Help: "Messages whose body was too large to keep in memory and was written to the spool " +
				"directory for the length of the transaction. A steady rate here is what tells you the " +
				"spool volume is load-bearing rather than dormant.",
		}, []string{"account"}),
		messageBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_message_bytes_total",
			Help: "Bytes relayed upstream, by account, as submitted after filtering and signing.",
		}, []string{"account"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_auth_failures_total",
			Help: "Refused authentications. Attempts on a username no account has are reported as " +
				unknownAccount + ", to keep the label bounded by configuration rather than by traffic.",
		}, []string{"account"}),
		milterDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_milter_decisions_total",
			Help: "Verdicts returned by each milter. unavailable counts the filter failing to answer, " +
				"whether the message was then let through or refused.",
		}, []string{"milter", "decision"}),
		dkimSignatures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_dkim_signatures_total",
			Help: "DKIM signing outcomes per domain. refused is a message whose account is not allowed " +
				"to send from that domain; a message with no key for its domain is not counted at all.",
		}, []string{"domain", "result"}),
		rateLimit: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_ratelimit_decisions_total",
			Help: "Quota decisions per account. error means the store was unreachable and the message " +
				"was refused for it, which is a failure of the relay's own infrastructure, not of the sender.",
		}, []string{"account", "decision"}),
		upstreamDelivery: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "mailout_upstream_delivery_seconds",
			Help: "Time spent handing a message to the upstream, successes and failures alike.",
			// Delivery is synchronous, so this is what the submitting
			// application waits on. The buckets span a fast local relay to the
			// upstream timeout.
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}),
		configReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mailout_config_reloads_total",
			Help: "Configuration reloads. A failed reload leaves the previous configuration in service, " +
				"so this is the only sign the relay is running on something stale.",
		}, []string{"result"}),
		accounts: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mailout_accounts",
			Help: "Accounts currently served.",
		}),
		accountsRejected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mailout_accounts_rejected",
			Help: "Accounts left out of the running configuration because their own settings are unusable.",
		}),
	}
	reg.MustRegister(
		m.messages, m.messagesSpooled, m.messageBytes, m.authFailures, m.milterDecisions, m.dkimSignatures,
		m.rateLimit, m.upstreamDelivery, m.configReloads, m.accounts, m.accountsRejected,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Registry exposes the collectors for tests that want to read them back.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves the exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}

func (m *Metrics) messageHandled(account, result string) {
	if m == nil {
		return
	}
	m.messages.WithLabelValues(account, result).Inc()
}

func (m *Metrics) messageSpooled(account string) {
	if m == nil {
		return
	}
	m.messagesSpooled.WithLabelValues(account).Inc()
}

func (m *Metrics) messageRelayed(account string, bytes int) {
	if m == nil {
		return
	}
	m.messages.WithLabelValues(account, ResultRelayed).Inc()
	m.messageBytes.WithLabelValues(account).Add(float64(bytes))
}

func (m *Metrics) authFailed(account string) {
	if m == nil {
		return
	}
	m.authFailures.WithLabelValues(account).Inc()
}

func (m *Metrics) milterDecided(milter, decision string) {
	if m == nil {
		return
	}
	m.milterDecisions.WithLabelValues(milter, decision).Inc()
}

func (m *Metrics) dkimResult(domain, result string) {
	if m == nil {
		return
	}
	m.dkimSignatures.WithLabelValues(domain, result).Inc()
}

func (m *Metrics) rateLimitDecided(account, decision string) {
	if m == nil {
		return
	}
	m.rateLimit.WithLabelValues(account, decision).Inc()
}

func (m *Metrics) upstreamDelivered(d time.Duration) {
	if m == nil {
		return
	}
	m.upstreamDelivery.Observe(d.Seconds())
}

func (m *Metrics) configReloaded(result string, served, rejected int) {
	if m == nil {
		return
	}
	m.configReloads.WithLabelValues(result).Inc()
	if result != "success" {
		// A refused reload changes nothing that is being served; leaving the
		// gauges alone is what keeps them describing what actually runs.
		return
	}
	m.accounts.Set(float64(served))
	m.accountsRejected.Set(float64(rejected))
}

// ServeMetrics serves the endpoint until ctx is cancelled. An empty address
// disables it and returns immediately.
//
// It is deliberately a plain HTTP server on its own port: it carries no
// credential and no message content, only counters, and Prometheus scrapes it
// from inside the cluster. It is never the SMTP port, so a scrape cannot be
// confused with a submission.
func ServeMetrics(ctx context.Context, addr string, m *Metrics, token func() string, log *slog.Logger) error {
	if addr == "" {
		return nil
	}
	if token == nil || token() == "" {
		log.Warn("metrics endpoint is unauthenticated: anyone who can reach it " +
			"learns which accounts are served, which domains are signed and how much each sends")
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", requireBearer(token, m.Handler()))
	srv := &http.Server{
		Handler: mux,
		// A scrape that hangs must not pin a connection forever; Prometheus
		// retries on its own schedule anyway.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Info("serving metrics", "addr", l.Addr().String(), "path", "/metrics")

	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// requireBearer gates a handler on a bearer token, read fresh on every request
// so that rotating it takes effect on the next reload rather than on a restart.
//
// No token configured means no gate: the standalone dataplane is a supported
// entry point and does not have an operator to generate one. That case is
// warned about at startup rather than left to be discovered.
func requireBearer(token func() string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := ""
		if token != nil {
			want = token()
		}
		if want == "" {
			next.ServeHTTP(w, r)
			return
		}
		// The scheme is required, not trimmed if present: TrimPrefix would
		// accept a bare token too, which is a laxity nobody asked for. RFC 6750
		// makes the scheme name case-insensitive.
		scheme, got, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			got = ""
		}
		// Constant time: the comparison is against a secret, and a scraper is
		// free to retry as often as it likes.
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mailout metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
