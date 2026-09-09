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
func TestEmptySenderPolicyAllowsNothing(t *testing.T) {
	// The inverse of what this used to assert. An account that was granted
	// nothing sends nothing: sending rights come from the gateway's owner, and
	// the old default let a tenant decide its own — on a gateway holding
	// several tenants' keys, that meant having another's domain signed.
	policy := newSenderPolicy(nil)
	for _, address := range []string{"anyone@anywhere.test", "", "weird", "app@example.test"} {
		if policy.allows(address) {
			t.Errorf("an empty policy allowed %q", address)
		}
	}
	if policy.canSign("anywhere.test") {
		t.Error("an empty policy signs something")
	}
	if !policy.empty() {
		t.Error("a policy compiled from nothing does not report itself empty")
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
	// A malformed entry must narrow the policy, never widen it. It used to be
	// possible for a policy built entirely from junk to report itself
	// "declared" and therefore non-empty; now it grants nothing, which is the
	// same answer arrived at more simply.
	policy := newSenderPolicy([]string{"no-at-sign", "@example.test", "app@", ""})
	if !policy.empty() {
		t.Error("a policy built only from malformed entries grants something")
	}
	for _, address := range []string{"app@example.test", "no-at-sign", "anything@anywhere.test"} {
		if policy.allows(address) {
			t.Errorf("a policy of malformed entries allowed %q", address)
		}
	}
}

// GrantedSubset is the one piece of this matching the operator needs: an
// account's own list can only narrow what its namespace was granted.
func TestGrantedSubset(t *testing.T) {
	granted := []string{"*@a.test", "noreply@b.test"}

	for name, tc := range map[string]struct {
		requested   []string
		wantAllowed []string
		wantRefused []string
	}{
		"nothing requested takes the whole grant": {
			nil, []string{"*@a.test", "noreply@b.test"}, nil,
		},
		"a subset of a granted domain": {
			[]string{"app@a.test"}, []string{"app@a.test"}, nil,
		},
		"the granted domain itself": {
			[]string{"*@a.test"}, []string{"*@a.test"}, nil,
		},
		"a domain granted only as one address": {
			// noreply@b.test is granted, *@b.test is not: an exact grant
			// covers itself and nothing more.
			[]string{"*@b.test"}, nil, []string{"*@b.test"},
		},
		"the exact address that was granted": {
			[]string{"noreply@b.test"}, []string{"noreply@b.test"}, nil,
		},
		"another address in that domain": {
			[]string{"ceo@b.test"}, nil, []string{"ceo@b.test"},
		},
		"a domain never granted": {
			[]string{"*@victim.test"}, nil, []string{"*@victim.test"},
		},
		"partly covered": {
			[]string{"app@a.test", "*@victim.test"},
			[]string{"app@a.test"}, []string{"*@victim.test"},
		},
		"malformed is refused, never granted": {
			[]string{"no-at-sign"}, nil, []string{"no-at-sign"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			allowed, refused := GrantedSubset(granted, tc.requested)
			if !equalStrings(allowed, tc.wantAllowed) {
				t.Errorf("allowed = %v, want %v", allowed, tc.wantAllowed)
			}
			if !equalStrings(refused, tc.wantRefused) {
				t.Errorf("refused = %v, want %v", refused, tc.wantRefused)
			}
		})
	}
}

// An empty grant covers nothing at all, whatever is asked for.
func TestGrantedSubsetWithNoGrant(t *testing.T) {
	allowed, refused := GrantedSubset(nil, []string{"app@a.test"})
	if len(allowed) != 0 {
		t.Errorf("allowed = %v with nothing granted", allowed)
	}
	if len(refused) != 1 {
		t.Errorf("refused = %v, want the one entry", refused)
	}
	// And an account asking for nothing gets nothing, rather than everything.
	if allowed, _ := GrantedSubset(nil, nil); len(allowed) != 0 {
		t.Errorf("allowed = %v from an empty grant and no request", allowed)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
