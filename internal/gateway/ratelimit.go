// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"
)

// rateLimitWindow is the counting period. Fixed rather than sliding: one key
// per account per window, incremented once, which is the only shape that stays
// a single-key operation — and therefore the only one that works unchanged on a
// Redis Cluster.
//
// The cost is the boundary effect: an account can spend its whole quota in the
// last second of a window and again in the first second of the next, so twice
// the quota can go out within one window's span. That is a documented property
// of fixed windows, not an accident, and it is the price of not needing a Lua
// script or a sorted set per account.
const rateLimitWindow = time.Minute

// RateLimit caps what one account may send. The limits apply to every account
// of the gateway alike: they are declared by the gateway's owner, and a
// MailoutAccount lives in a tenant's own namespace — a per-account override
// there would be the tenant setting its own quota.
type RateLimit struct {
	Store RateLimitStore `json:"store"`
	// MessagesPerMinute and RecipientsPerMinute are counted separately: a
	// thousand messages to one recipient and one message to a thousand
	// recipients are the same amount of mail, and only the second is caught by
	// a message count.
	//
	// Zero leaves that dimension uncounted.
	MessagesPerMinute   int `json:"messagesPerMinute,omitempty"`
	RecipientsPerMinute int `json:"recipientsPerMinute,omitempty"`
}

// RateLimitStore is the shared counter every replica of the gateway increments.
// It is referenced, never deployed: the operator does not run a Valkey for you,
// because the store is a piece of infrastructure with its own lifecycle,
// backups and upgrade schedule.
type RateLimitStore struct {
	// Addresses is one address for a standalone server, the Sentinel addresses
	// when MasterName is set, or the cluster seed nodes.
	//
	// Careful: several addresses without MasterName means cluster mode. A plain
	// primary/replica trio listed here without a MasterName would be taken for a
	// cluster and fail to talk to it, which is why the deduced mode is logged at
	// startup.
	Addresses []string `json:"addresses"`
	// MasterName is the Sentinel master name. Setting it selects Sentinel
	// failover, which is what a Valkey deployed as one primary and two replicas
	// wants.
	MasterName string `json:"masterName,omitempty"`
	DB         int    `json:"db,omitempty"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// SentinelUsername and SentinelPassword authenticate to the Sentinels
	// themselves, which usually have credentials of their own.
	SentinelUsername string `json:"sentinelUsername,omitempty"`
	SentinelPassword string `json:"sentinelPassword,omitempty"`

	TLS                bool   `json:"tls,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	RootCAPEM          string `json:"rootCAPEM,omitempty"`

	// Timeout bounds every call to the store. It is on the path of every
	// message, so it must be short: the whole point of failing closed is that a
	// missing store stops mail, and a long timeout turns that into a hang.
	//
	// It is per call, not per message: a message counted against both dimensions
	// makes two calls, so a message can wait up to twice this.
	Timeout Duration `json:"timeout,omitempty"`
}

const defaultRateLimitTimeout = 2 * time.Second

// sameStore reports whether two store configurations describe the same
// connection, so that a reload that only changed accounts does not drop and
// rebuild the connection pool.
func sameStore(a, b RateLimitStore) bool {
	return slices.Equal(a.Addresses, b.Addresses) &&
		a.MasterName == b.MasterName &&
		a.DB == b.DB &&
		a.Username == b.Username &&
		a.Password == b.Password &&
		a.SentinelUsername == b.SentinelUsername &&
		a.SentinelPassword == b.SentinelPassword &&
		a.TLS == b.TLS &&
		a.InsecureSkipVerify == b.InsecureSkipVerify &&
		a.RootCAPEM == b.RootCAPEM &&
		a.Timeout == b.Timeout
}

// limiter counts against the shared store. A nil limiter counts nothing, which
// is what a gateway with no rateLimit gets.
type limiter struct {
	client  redis.UniversalClient
	gateway string
	limits  RateLimit
	log     *slog.Logger
	metrics *Metrics
}

func newLimiter(cfg *Config, log *slog.Logger, metrics *Metrics) (*limiter, error) {
	if cfg.RateLimit == nil {
		return nil, nil
	}
	store := cfg.RateLimit.Store
	if len(store.Addresses) == 0 {
		return nil, fmt.Errorf("rateLimit.store.addresses is required")
	}

	opts := &redis.UniversalOptions{
		Addrs:            store.Addresses,
		MasterName:       store.MasterName,
		DB:               store.DB,
		Username:         store.Username,
		Password:         store.Password,
		SentinelUsername: store.SentinelUsername,
		SentinelPassword: store.SentinelPassword,
		// Counters are read back in the same call that writes them, so they can
		// never be served by a replica: INCR is a write and goes to the primary
		// by construction. Leaving the read routing at its default is what keeps
		// it that way.
	}
	if store.TLS {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: store.InsecureSkipVerify, //nolint:gosec // opt-in, for a self-signed test store
		}
		if store.RootCAPEM != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(store.RootCAPEM)) {
				return nil, fmt.Errorf("rateLimit.store: no certificate found in rootCAPEM")
			}
			tlsConfig.RootCAs = pool
		}
		opts.TLSConfig = tlsConfig
	}

	l := &limiter{
		client:  redis.NewUniversalClient(opts),
		gateway: cfg.Hostname,
		limits:  *cfg.RateLimit,
		log:     log,
		metrics: metrics,
	}
	// The mode is deduced from the options rather than declared, so a
	// misconfiguration — three replicas listed without a masterName, taken for a
	// cluster — is otherwise silent until the first message is refused.
	if store.Password != "" && !store.TLS {
		l.log.Warn("quota store password will be sent in clear: rateLimit.store.tls is false",
			"mode", storeMode(store))
	}
	if store.InsecureSkipVerify {
		l.log.Warn("quota store certificate verification is disabled")
	}
	l.log.Info("rate limiting enabled",
		"mode", storeMode(store), "addresses", len(store.Addresses),
		"messagesPerMinute", l.limits.MessagesPerMinute,
		"recipientsPerMinute", l.limits.RecipientsPerMinute)
	return l, nil
}

// storeMode names what NewUniversalClient will build from these addresses.
func storeMode(store RateLimitStore) string {
	switch {
	case store.MasterName != "":
		return "sentinel"
	case len(store.Addresses) > 1:
		return "cluster"
	default:
		return "standalone"
	}
}

func (l *limiter) empty() bool { return l == nil || l.client == nil }

func (l *limiter) close() {
	if l == nil || l.client == nil {
		return
	}
	_ = l.client.Close()
}

// errOverQuota is a temporary refusal: the client should hold the message and
// try again, which is exactly what 4.2.2 (mailbox full / quota exceeded) tells
// it to do.
func errOverQuota(what string) *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         452,
		EnhancedCode: smtp.EnhancedCode{4, 2, 2},
		Message:      fmt.Sprintf("Too many %s for this account, try again later", what),
	}
}

// errStoreUnavailable is the fail-closed answer. Refusing to relay when the
// counter cannot be reached makes the store a single point of failure on the
// path of every message — deliberately: a quota that stops being enforced the
// moment its store hiccups is not a quota. This is what the store's own high
// availability is there to cover.
func errStoreUnavailable() *smtp.SMTPError {
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 2},
		Message:      "Quota store unavailable, try again later",
	}
}

// check counts one message and its recipients against the account's quota.
func (l *limiter) check(ctx context.Context, account string, recipients int) error {
	if l.empty() {
		return nil
	}
	timeout := l.limits.Store.Timeout.D()
	if timeout == 0 {
		timeout = defaultRateLimitTimeout
	}

	for _, dimension := range []struct {
		name  string
		what  string
		limit int
		by    int64
	}{
		{"messages", "messages", l.limits.MessagesPerMinute, 1},
		{"recipients", "recipients", l.limits.RecipientsPerMinute, int64(recipients)},
	} {
		if dimension.limit <= 0 || dimension.by <= 0 {
			continue
		}
		count, err := l.increment(ctx, account, dimension.name, dimension.by, timeout)
		if err != nil {
			l.log.Error("quota store unreachable, refusing the message",
				"account", account, "dimension", dimension.name, "err", err)
			l.metrics.rateLimitDecided(account, rateLimitError)
			return errStoreUnavailable()
		}
		if count > int64(dimension.limit) {
			l.log.Warn("account over quota",
				"account", account, "dimension", dimension.name,
				"count", count, "limit", dimension.limit)
			l.metrics.rateLimitDecided(account, rateLimitDenied)
			return errOverQuota(dimension.what)
		}
	}
	l.metrics.rateLimitDecided(account, rateLimitAllowed)
	return nil
}

// increment adds to one counter and returns its new value.
//
// INCRBY then EXPIRE ... NX, pipelined: the NX is what stops every message from
// pushing the window further out, which would turn a fixed window into a quota
// that never resets for a busy account. Both commands address the same single
// key, so this is safe on a cluster without a hash tag — and without one, keys
// spread across slots instead of piling onto whichever slot a gateway's tag
// happened to hash to.
func (l *limiter) increment(ctx context.Context, account, dimension string, by int64, timeout time.Duration) (int64, error) {
	// The timeout bounds this call rather than the whole check, which is what
	// its documentation promises. Bounding the check instead would let a slow
	// first dimension eat the budget of the second, and refuse a message
	// fail-closed while the store was in fact answering.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	key := l.key(account, dimension)
	pipe := l.client.Pipeline()
	incr := pipe.IncrBy(ctx, key, by)
	pipe.ExpireNX(ctx, key, rateLimitWindow*2)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Result()
}

// key names one counter. No braces anywhere: in cluster mode `{...}` is the
// hash tag, and writing one here would route every counter of a gateway to a
// single slot — turning the shard that owns it into the hot spot for the whole
// relay.
func (l *limiter) key(account, dimension string) string {
	window := time.Now().Unix() / int64(rateLimitWindow.Seconds())
	return fmt.Sprintf("mailout:%s:%s:%s:%d", l.gateway, account, dimension, window)
}
