// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import "testing"

func TestSenderPolicyAllows(t *testing.T) {
	policy := newSenderPolicy([]string{
		"app@example.test",
		"*@mail.example.test",
		// Casing must not matter: these come from YAML written by hand.
		"*@OTHER.test",
	})

	tests := []struct {
		address string
		want    bool
	}{
		{"app@example.test", true},
		{"APP@EXAMPLE.TEST", true},
		{"other@example.test", false},
		{"anything@mail.example.test", true},
		{"anything@sub.mail.example.test", false},
		{"x@other.test", true},
		{"Application <app@example.test>", true},
		{"<app@example.test>", true},
		{"", false},
		{"not-an-address", false},
	}
	for _, tc := range tests {
		if got := policy.allows(tc.address); got != tc.want {
			t.Errorf("allows(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}

// An empty policy places no restriction on what may be sent — that is what
// keeps existing accounts working.
func TestEmptySenderPolicyAllowsEverything(t *testing.T) {
	policy := newSenderPolicy(nil)
	if !policy.empty() {
		t.Fatal("a policy built from nothing should report itself empty")
	}
	for _, address := range []string{"anyone@anywhere.test", "", "weird"} {
		if !policy.allows(address) {
			t.Errorf("an empty policy refused %q", address)
		}
	}
}

// The signable domains are what gates DKIM: a key is only ever applied to a
// domain the account is allowed to send from. An empty policy signs nothing,
// which is the whole point — declaring a sender is what earns a signature.
func TestSenderPolicySignableDomains(t *testing.T) {
	policy := newSenderPolicy([]string{"app@example.test", "*@other.test", "bad-entry"})

	if !policy.canSign("example.test") {
		t.Error("an exact address must make its domain signable")
	}
	if !policy.canSign("other.test") {
		t.Error("a wildcard must make its domain signable")
	}
	if policy.canSign("EXAMPLE.TEST") != true {
		t.Error("domain matching must be case-insensitive")
	}
	if policy.canSign("elsewhere.test") {
		t.Error("an undeclared domain must not be signable")
	}

	empty := newSenderPolicy(nil)
	if empty.canSign("example.test") {
		t.Error("an account with no declared sender must not sign anything")
	}
}

func TestSenderPolicyRejectsMalformedEntries(t *testing.T) {
	// A malformed entry must not silently widen the policy.
	policy := newSenderPolicy([]string{"no-at-sign", "@no-local-part", "*@"})
	if policy.empty() {
		t.Fatal("the policy has entries, so it is not empty")
	}
	if policy.allows("anyone@anywhere.test") {
		t.Error("malformed entries must not let everything through")
	}
	if policy.canSign("anywhere.test") {
		t.Error("malformed entries must not make a domain signable")
	}
}
