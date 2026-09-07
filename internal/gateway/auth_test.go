// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"errors"
	"testing"

	"github.com/emersion/go-sasl"
)

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

func testStore(t *testing.T) *accountStore {
	t.Helper()
	return newAccountStore([]Account{
		{Username: "app1", PasswordHash: mustHash(t, "s3cret")},
		{Username: "app2", PasswordHash: mustHash(t, "other"), Disabled: true},
	})
}

func TestAccountStoreAuthenticate(t *testing.T) {
	store := testStore(t)

	tests := []struct {
		name     string
		user     string
		password string
		wantErr  error
	}{
		{"valid", "app1", "s3cret", nil},
		{"wrong password", "app1", "nope", errAuthFailed},
		{"unknown user", "ghost", "s3cret", errAuthFailed},
		{"username is case sensitive", "APP1", "s3cret", errAuthFailed},
		{"disabled account", "app2", "other", errAccountDisabled},
		{"empty password", "app1", "", errAuthFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acct, err := store.authenticate(tc.user, tc.password)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("authenticate(%q, %q) error = %v, want %v", tc.user, tc.password, err, tc.wantErr)
			}
			if tc.wantErr == nil && acct.Username != tc.user {
				t.Fatalf("got account %q, want %q", acct.Username, tc.user)
			}
		})
	}
}

// A username that does not exist must still cost a bcrypt comparison, so that
// response time does not leak which accounts exist.
func TestAccountStoreUnknownUserStillHashes(t *testing.T) {
	store := newAccountStore(nil)
	if _, err := store.authenticate("ghost", "whatever"); !errors.Is(err, errAuthFailed) {
		t.Fatalf("want errAuthFailed, got %v", err)
	}
	if store.dummyHash == "" {
		t.Fatal("store has no dummy hash to compare against")
	}
}

func TestLoginSASLServer(t *testing.T) {
	var gotUser, gotPass string
	srv := newLoginServer(func(username, password string) error {
		gotUser, gotPass = username, password
		return nil
	})

	challenge, done, err := srv.Next(nil)
	if err != nil || done {
		t.Fatalf("first Next: err=%v done=%v", err, done)
	}
	if string(challenge) != "Username:" {
		t.Fatalf("first challenge = %q, want %q", challenge, "Username:")
	}
	challenge, done, err = srv.Next([]byte("app1"))
	if err != nil || done {
		t.Fatalf("second Next: err=%v done=%v", err, done)
	}
	if string(challenge) != "Password:" {
		t.Fatalf("second challenge = %q, want %q", challenge, "Password:")
	}
	if _, done, err = srv.Next([]byte("s3cret")); err != nil || !done {
		t.Fatalf("third Next: err=%v done=%v", err, done)
	}
	if gotUser != "app1" || gotPass != "s3cret" {
		t.Fatalf("authenticator got (%q, %q)", gotUser, gotPass)
	}
}

func TestLoginSASLServerPropagatesFailure(t *testing.T) {
	srv := newLoginServer(func(string, string) error { return errAuthFailed })
	_, _, _ = srv.Next(nil)
	_, _, _ = srv.Next([]byte("app1"))
	if _, _, err := srv.Next([]byte("bad")); !errors.Is(err, errAuthFailed) {
		t.Fatalf("want errAuthFailed, got %v", err)
	}
}

// The PLAIN server from go-sasl must be wired to the same authenticator.
func TestPlainSASLServerWiring(t *testing.T) {
	store := testStore(t)
	var authenticated *Account
	srv := sasl.NewPlainServer(func(identity, username, password string) error {
		acct, err := store.authenticate(username, password)
		authenticated = acct
		return err
	})
	if _, _, err := srv.Next([]byte("\x00app1\x00s3cret")); err != nil {
		t.Fatalf("PLAIN auth failed: %v", err)
	}
	if authenticated == nil || authenticated.Username != "app1" {
		t.Fatalf("got %+v", authenticated)
	}
}
