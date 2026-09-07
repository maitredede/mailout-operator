// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package gateway

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/emersion/go-msgauth/dkim"
	"log/slog"
	"os"
	"strings"
)

// DKIMKey is one signing key, published in DNS as
// <selector>._domainkey.<domain>.
type DKIMKey struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	// PrivateKeyPEM or PrivateKeyFile holds an RSA or Ed25519 key in PKCS#1 or
	// PKCS#8 form. In a cluster this comes from a Secret.
	PrivateKeyPEM  string `json:"privateKeyPEM,omitempty"`
	PrivateKeyFile string `json:"privateKeyFile,omitempty"`
	// HeaderKeys restricts which headers are signed. Empty means the library's
	// default set, which is the right choice unless you know otherwise.
	HeaderKeys []string `json:"headerKeys,omitempty"`
}

// dkimSigner signs outgoing messages. Signing happens after the milters, so the
// signature covers the body the filters actually left behind.
type dkimSigner struct {
	byDomain map[string]*loadedDKIMKey
	log      *slog.Logger
}

type loadedDKIMKey struct {
	domain     string
	selector   string
	signer     crypto.Signer
	headerKeys []string
}

func newDKIMSigner(keys []DKIMKey, log *slog.Logger) (*dkimSigner, error) {
	s := &dkimSigner{byDomain: make(map[string]*loadedDKIMKey, len(keys)), log: log}
	for i, k := range keys {
		if k.Domain == "" || k.Selector == "" {
			return nil, fmt.Errorf("dkim[%d]: domain and selector are required", i)
		}
		signer, err := loadDKIMPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("dkim %s/%s: %w", k.Selector, k.Domain, err)
		}
		domain := strings.ToLower(k.Domain)
		if _, dup := s.byDomain[domain]; dup {
			return nil, fmt.Errorf("dkim: two keys for domain %s", domain)
		}
		s.byDomain[domain] = &loadedDKIMKey{
			domain:     domain,
			selector:   k.Selector,
			signer:     signer,
			headerKeys: k.HeaderKeys,
		}
	}
	return s, nil
}

// empty reports whether there is nothing to sign with.
func (s *dkimSigner) empty() bool { return len(s.byDomain) == 0 }

// sign adds a DKIM-Signature header in place. A message whose domain has no key
// is left alone: signing it under some other domain would break DMARC
// alignment, which is worse than not signing at all.
func (s *dkimSigner) sign(msg *Message) error {
	key := s.keyFor(msg)
	if key == nil {
		s.log.Debug("no DKIM key for this sender, not signing",
			"from", msg.From, "account", msg.Account)
		return nil
	}
	opts := &dkim.SignOptions{
		Domain:     key.domain,
		Selector:   key.selector,
		Signer:     key.signer,
		HeaderKeys: key.headerKeys,
	}
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(msg.Data), opts); err != nil {
		return fmt.Errorf("sign for %s: %w", key.domain, err)
	}
	msg.Data = signed.Bytes()
	return nil
}

// keyFor picks the key matching the envelope sender, falling back to the From
// header — an application may legitimately submit with an empty envelope
// sender.
func (s *dkimSigner) keyFor(msg *Message) *loadedDKIMKey {
	if key := s.byDomain[domainOf(msg.From)]; key != nil {
		return key
	}
	parsed, err := parseMessage(msg.Data)
	if err != nil {
		return nil
	}
	for _, h := range parsed.Headers {
		if strings.EqualFold(h.Name, "From") {
			return s.byDomain[domainOf(h.Value)]
		}
	}
	return nil
}

// domainOf extracts the domain from an address, tolerating a display name and
// angle brackets.
func domainOf(address string) string {
	addr := address
	if start := strings.LastIndex(addr, "<"); start >= 0 {
		if end := strings.Index(addr[start:], ">"); end > 0 {
			addr = addr[start+1 : start+end]
		}
	}
	_, domain, found := strings.Cut(addr, "@")
	if !found {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(domain))
}

func loadDKIMPrivateKey(k DKIMKey) (crypto.Signer, error) {
	raw := []byte(k.PrivateKeyPEM)
	if k.PrivateKeyFile != "" {
		var err error
		if raw, err = os.ReadFile(k.PrivateKeyFile); err != nil {
			return nil, fmt.Errorf("read privateKeyFile: %w", err)
		}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("privateKeyPEM or privateKeyFile is required")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return parsePrivateKey(block)
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch typed := key.(type) {
		case *rsa.PrivateKey:
			return typed, nil
		case ed25519.PrivateKey:
			return typed, nil
		default:
			return nil, fmt.Errorf("unsupported key type %T, want RSA or Ed25519", key)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("key is neither PKCS#8 nor PKCS#1")
}
