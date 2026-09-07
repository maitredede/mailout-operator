// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import "strings"

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
	// declared is true as soon as the account listed anything, malformed
	// entries included: an unparsable entry must narrow the policy, never widen
	// it back to "everything".
	declared bool
}

// newSenderPolicy compiles an account's allowedSenders. Entries are either an
// exact address (app@example.com) or a whole domain (*@example.com).
func newSenderPolicy(allowedSenders []string) *senderPolicy {
	p := &senderPolicy{
		addresses: make(map[string]bool),
		domains:   make(map[string]bool),
		declared:  len(allowedSenders) > 0,
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

// empty reports whether the account declared no sender at all, in which case it
// may send from anywhere — and have nothing signed.
func (p *senderPolicy) empty() bool { return !p.declared }

// allows reports whether an address may be used as a sender. It tolerates a
// display name and angle brackets, since it is also applied to the From header.
func (p *senderPolicy) allows(address string) bool {
	if p.empty() {
		return true
	}
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
// account that declared nothing signs nothing: declaring a sender is what earns
// a signature.
func (p *senderPolicy) canSign(domain string) bool {
	if p.empty() {
		return false
	}
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
