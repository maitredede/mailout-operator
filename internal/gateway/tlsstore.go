// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// certStore resolves the certificate to serve for a given SNI name. It is
// immutable; a configuration change builds a new one and swaps it in.
//
// It backs tls.Config.GetCertificate, which go-smtp uses both for STARTTLS
// (tls.Server on an established connection) and for implicit TLS listeners
// (tls.Listen) — so SNI works on both ports.
type certStore struct {
	byName     map[string]*tls.Certificate
	wildcards  map[string]*tls.Certificate
	defaultCrt *tls.Certificate
}

func newCertStore(cfg TLSConfig) (*certStore, error) {
	if len(cfg.Certificates) == 0 {
		return nil, fmt.Errorf("no certificate configured")
	}
	s := &certStore{
		byName:    make(map[string]*tls.Certificate),
		wildcards: make(map[string]*tls.Certificate),
	}
	for i, ref := range cfg.Certificates {
		name := ref.Name
		if name == "" {
			name = fmt.Sprintf("certificates[%d]", i)
		}
		cert, err := loadKeyPair(ref)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: %w", name, err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("certificate %s: parse leaf: %w", name, err)
		}
		cert.Leaf = leaf
		for _, dnsName := range dnsNamesOf(leaf) {
			if suffix, ok := strings.CutPrefix(dnsName, "*."); ok {
				s.wildcards[strings.ToLower(suffix)] = cert
				continue
			}
			s.byName[strings.ToLower(dnsName)] = cert
		}
		if i == 0 {
			s.defaultCrt = cert
		}
		if cfg.DefaultCertificate != "" && ref.Name == cfg.DefaultCertificate {
			s.defaultCrt = cert
		}
	}
	return s, nil
}

// getCertificate implements tls.Config.GetCertificate. An unknown or absent
// server name falls back to the default certificate rather than failing the
// handshake: a mail client that does not send SNI must still be able to
// connect.
func (s *certStore) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if cert, ok := s.byName[name]; ok {
		return cert, nil
	}
	if _, parent, found := strings.Cut(name, "."); found {
		if cert, ok := s.wildcards[parent]; ok {
			return cert, nil
		}
	}
	return s.defaultCrt, nil
}

// tlsConfig returns the server-side TLS configuration serving this store.
func (s *certStore) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.getCertificate,
	}
}

func loadKeyPair(ref CertificateRef) (*tls.Certificate, error) {
	certPEM, keyPEM := []byte(ref.CertPEM), []byte(ref.KeyPEM)
	if ref.CertFile != "" {
		var err error
		if certPEM, err = os.ReadFile(ref.CertFile); err != nil {
			return nil, fmt.Errorf("read certFile: %w", err)
		}
		if keyPEM, err = os.ReadFile(ref.KeyFile); err != nil {
			return nil, fmt.Errorf("read keyFile: %w", err)
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid keypair: %w", err)
	}
	return &cert, nil
}

// dnsNamesOf returns the names a certificate is valid for, falling back to the
// common name when the certificate carries no SAN.
func dnsNamesOf(leaf *x509.Certificate) []string {
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames
	}
	if leaf.Subject.CommonName != "" {
		return []string{leaf.Subject.CommonName}
	}
	return nil
}
