// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"sort"
	"strings"
)

// senderPolicy decides which addresses an account may send from, and therefore
// which domains it may have signed.
//
// Two things it deliberately conflates: the right to send from a domain and the
// right to have that domain signed. A DKIM signature says "this domain vouches
// for this message"; letting an account be signed for a domain it may not send
// from would let one tenant vouch for another's.
type senderPolicy struct {
	// addresses are the exact addresses allowed, lowercased.
	addresses map[string]bool
	// domains are the domains allowed wholesale, lowercased, from *@domain
	// entries.
	domains map[string]bool
}

// newSenderPolicy compiles an account's allowedSenders. Entries are either an
// exact address (app@example.com) or a whole domain (*@example.com).
func newSenderPolicy(allowedSenders []string) *senderPolicy {
	p := &senderPolicy{
		addresses: make(map[string]bool),
		domains:   make(map[string]bool),
	}
	for _, entry := range allowedSenders {
		entry = strings.ToLower(strings.TrimSpace(entry))
		local, domain, found := strings.Cut(entry, "@")
		if !found || domain == "" || local == "" {
			// Malformed. It is rejected at admission time; here it simply
			// grants nothing.
			continue
		}
		if local == "*" {
			p.domains[domain] = true
			continue
		}
		p.addresses[entry] = true
	}
	return p
}

// empty reports whether the policy grants nothing, in which case the account
// may send nothing at all.
//
// This used to mean the opposite — an account that declared no sender could
// send from anywhere, unsigned. That default put the decision in the tenant's
// hands: on a gateway holding keys for several tenants, an account wrote
// another's domain into its own list and had it signed. Sending rights are now
// granted by the gateway's owner, and nothing granted means nothing sent.
func (p *senderPolicy) empty() bool { return len(p.addresses) == 0 && len(p.domains) == 0 }

// allows reports whether an address may be used as a sender. It tolerates a
// display name and angle brackets, since it is also applied to the From header.
func (p *senderPolicy) allows(address string) bool {
	addr := strings.ToLower(bareAddress(address))
	if addr == "" {
		return false
	}
	if p.addresses[addr] {
		return true
	}
	_, domain, found := strings.Cut(addr, "@")
	return found && p.domains[domain]
}

// canSign reports whether a domain may be signed on this account's behalf. An
// account granted nothing signs nothing, which follows from it not being
// allowed to send there either.
func (p *senderPolicy) canSign(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if p.domains[domain] {
		return true
	}
	// An exact address makes its own domain signable: the account is a
	// legitimate sender there.
	for address := range p.addresses {
		if _, addressDomain, found := strings.Cut(address, "@"); found && addressDomain == domain {
			return true
		}
	}
	return false
}

// bareAddress strips a display name and angle brackets, so that
// `App <app@example.test>` and `app@example.test` compare equal.
func bareAddress(address string) string {
	addr := strings.TrimSpace(address)
	if start := strings.LastIndex(addr, "<"); start >= 0 {
		if end := strings.Index(addr[start:], ">"); end > 0 {
			addr = addr[start+1 : start+end]
		}
	}
	addr = strings.TrimSpace(addr)
	if !strings.Contains(addr, "@") {
		return ""
	}
	return addr
}

// covers reports whether this policy grants everything another one asks for.
//
// It is what makes an account's own allowedSenders a narrowing rather than a
// request: *@example.com covers app@example.com, and an exact address covers
// only itself.
func (p *senderPolicy) covers(requested []string) (uncovered []string) {
	for _, entry := range requested {
		normalized := strings.ToLower(strings.TrimSpace(entry))
		local, domain, found := strings.Cut(normalized, "@")
		switch {
		case !found || domain == "" || local == "":
			// Malformed: granted by nothing, so it is reported rather than
			// quietly dropped.
			uncovered = append(uncovered, entry)
		case local == "*":
			if !p.domains[domain] {
				uncovered = append(uncovered, entry)
			}
		case !p.domains[domain] && !p.addresses[normalized]:
			uncovered = append(uncovered, entry)
		}
	}
	return uncovered
}

// entries lists what the policy grants, in a stable order, in the same syntax
// it was compiled from.
func (p *senderPolicy) entries() []string {
	out := make([]string, 0, len(p.addresses)+len(p.domains))
	for domain := range p.domains {
		out = append(out, "*@"+domain)
	}
	for address := range p.addresses {
		out = append(out, address)
	}
	sort.Strings(out)
	return out
}

// GrantedSubset splits what an account asks for into what its grant covers and
// what it does not.
//
// It is the one piece of this matching the operator needs: the effective policy
// of an account is computed before the configuration is rendered, so the
// dataplane receives a resolved list and never has to know about namespaces.
// Exported rather than reimplemented there, because two implementations of the
// same security rule is one too many.
//
// An account that asks for nothing gets the whole grant: the gateway's owner
// has already decided, and making every tenant restate it would only add a
// place for the two to disagree.
func GrantedSubset(granted, requested []string) (allowed, refused []string) {
	policy := newSenderPolicy(granted)
	if len(requested) == 0 {
		return policy.entries(), nil
	}
	refused = policy.covers(requested)
	refusedSet := make(map[string]bool, len(refused))
	for _, entry := range refused {
		refusedSet[entry] = true
	}
	for _, entry := range requested {
		if !refusedSet[entry] {
			allowed = append(allowed, entry)
		}
	}
	return allowed, refused
}
