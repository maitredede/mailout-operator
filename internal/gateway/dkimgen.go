// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// GeneratedDKIMKey is a new signing key and the DNS record that publishes it.
type GeneratedDKIMKey struct {
	PrivateKeyPEM string
	// DNSRecordName is the name to create, e.g. "mail._domainkey.example.com".
	DNSRecordName string
	// DNSRecordValue is the TXT value to publish.
	DNSRecordValue string
}

// GenerateDKIMKey creates a signing key. algorithm is "rsa" (2048 bits, what
// every verifier supports) or "ed25519" (shorter, but not universally
// verified yet — publish it alongside an RSA key, never alone).
func GenerateDKIMKey(algorithm, domain, selector string) (*GeneratedDKIMKey, error) {
	var (
		privDER []byte
		pubDER  []byte
		keyType string
		err     error
	)
	switch algorithm {
	case "", "rsa":
		key, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			return nil, fmt.Errorf("generate RSA key: %w", genErr)
		}
		if privDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
			return nil, err
		}
		if pubDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey); err != nil {
			return nil, err
		}
		keyType = "rsa"
	case "ed25519":
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, fmt.Errorf("generate Ed25519 key: %w", genErr)
		}
		if privDER, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return nil, err
		}
		// Ed25519 DKIM records carry the raw 32-byte public key, not a PKIX
		// wrapper (RFC 8463).
		pubDER = pub
		keyType = "ed25519"
	default:
		return nil, fmt.Errorf("unknown algorithm %q, want rsa or ed25519", algorithm)
	}

	record := fmt.Sprintf("v=DKIM1; k=%s; p=%s", keyType, base64.StdEncoding.EncodeToString(pubDER))
	return &GeneratedDKIMKey{
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		DNSRecordName:  fmt.Sprintf("%s._domainkey.%s", selector, domain),
		DNSRecordValue: record,
	}, nil
}
