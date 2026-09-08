// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// A hash tag would route every counter of a gateway to one slot in cluster
// mode, making that shard the hot spot for the whole relay. Nothing here may
// contain braces.
func TestQuotaKeyCarriesNoHashTag(t *testing.T) {
	l := &limiter{gateway: "mail.example.com"}
	key := l.key("billing.invoicing", "messages")

	if strings.ContainsAny(key, "{}") {
		t.Fatalf("key %q carries a cluster hash tag", key)
	}
	for _, want := range []string{"mailout:", "mail.example.com", "billing.invoicing", "messages"} {
		if !strings.Contains(key, want) {
			t.Errorf("key %q does not carry %q", key, want)
		}
	}
	// Two accounts must never share a counter.
	if other := l.key("other.app", "messages"); other == key {
		t.Errorf("two accounts share the key %q", key)
	}
	if other := l.key("billing.invoicing", "recipients"); other == key {
		t.Errorf("both dimensions share the key %q", key)
	}
}

// The window is part of the key, which is what makes the counter reset without
// anything having to delete it.
func TestQuotaKeyChangesWithTheWindow(t *testing.T) {
	l := &limiter{gateway: "gw"}
	key := l.key("app", "messages")
	suffix := key[strings.LastIndex(key, ":")+1:]
	window := time.Now().Unix() / int64(rateLimitWindow.Seconds())
	if suffix != strconv.FormatInt(window, 10) {
		t.Fatalf("key window = %s, want %d", suffix, window)
	}
}

// The deduced mode is what tells an operator whether their three addresses were
// understood as a cluster or as Sentinel — the one misconfiguration that is
// otherwise silent until mail stops.
func TestStoreModeIsDeducedFromTheAddresses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store RateLimitStore
		want  string
	}{
		{"one address", RateLimitStore{Addresses: []string{"valkey:6379"}}, "standalone"},
		{"several addresses", RateLimitStore{Addresses: []string{"a:6379", "b:6379", "c:6379"}}, "cluster"},
		{"sentinel", RateLimitStore{
			Addresses:  []string{"s1:26379", "s2:26379", "s3:26379"},
			MasterName: "mailout",
		}, "sentinel"},
		// The trap: a primary and its replicas listed without a masterName.
		{"replicas without masterName", RateLimitStore{
			Addresses: []string{"primary:6379", "replica1:6379", "replica2:6379"},
		}, "cluster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := storeMode(tc.store); got != tc.want {
				t.Errorf("storeMode = %s, want %s", got, tc.want)
			}
		})
	}
}

// Every field of the store must be compared: a change that goes unnoticed keeps
// the previous connection pool, so a rotated password would leave the gateway
// talking to the store with a credential that no longer works — and since it
// fails closed, that stops mail.
//
// The fields are walked by reflection rather than listed, so that adding one to
// RateLimitStore without teaching sameStore about it fails here instead of in
// production.
func TestSameStoreComparesEveryField(t *testing.T) {
	base := RateLimitStore{
		Addresses: []string{"valkey:6379"},
		Password:  "s3cret",
		DB:        1,
	}
	if !sameStore(base, base) {
		t.Fatal("a store is not the same as itself")
	}

	typ := reflect.TypeOf(base)
	for i := range typ.NumField() {
		field := typ.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			changed := base
			changed.Addresses = append([]string(nil), base.Addresses...)
			v := reflect.ValueOf(&changed).Elem().Field(i)
			switch v.Kind() {
			case reflect.String:
				v.SetString(v.String() + "-other")
			case reflect.Int, reflect.Int64:
				v.SetInt(v.Int() + 1)
			case reflect.Bool:
				v.SetBool(!v.Bool())
			case reflect.Slice:
				v.Set(reflect.ValueOf([]string{"other:6379", "third:6379"}))
			default:
				t.Fatalf("no mutation known for %s (%s): teach this test about it", field.Name, v.Kind())
			}
			if sameStore(base, changed) {
				t.Errorf("a change to %s went unnoticed, so the connection pool would be kept", field.Name)
			}
		})
	}
}

// Fail-closed is the whole point: a store that cannot be reached must stop mail
// with a temporary error, not let it through uncounted.
func TestUnreachableStoreRefusesTheMessage(t *testing.T) {
	// A port nothing listens on: bound, then released.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := l.Addr().String()
	_ = l.Close()

	gw := newTestGateway(t, func(cfg *Config) {
		cfg.RateLimit = &RateLimit{
			Store: RateLimitStore{
				Addresses: []string{dead},
				Timeout:   Duration(500 * time.Millisecond),
			},
			MessagesPerMinute: 10,
		}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	err = c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("the message was relayed although the quota store is unreachable")
	}
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 451 {
		t.Fatalf("error = %v, want a 451", err)
	}
	if got := len(gw.upstream.received()); got != 0 {
		t.Fatalf("upstream received %d messages, want 0", got)
	}
	if got := counter(t, gw, "mailout_ratelimit_decisions_total",
		map[string]string{"account": testAccount, "decision": rateLimitError}); got != 1 {
		t.Errorf("store-error decisions = %v, want 1", got)
	}
}

// A gateway with no rateLimit counts nothing and must not pay for a store it
// does not have.
func TestNoRateLimitMeansNoStore(t *testing.T) {
	gw := newTestGateway(t)
	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := c.SendMail("app@example.test", []string{"dest@example.test"},
		strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
}
