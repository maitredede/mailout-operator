// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/maitredede/mailout-operator/internal/pki"
)

func testCertStore(t *testing.T) (*certStore, *pki.CA) {
	t.Helper()
	ca, err := pki.NewCA("mailout-test")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	first, err := ca.Issue("mail.first.test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, err := ca.Issue("mail.second.test", "alias.second.test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	store, err := newCertStore(TLSConfig{
		Certificates: []CertificateRef{
			{Name: "first", CertPEM: string(first.CertPEM), KeyPEM: string(first.KeyPEM)},
			{Name: "second", CertPEM: string(second.CertPEM), KeyPEM: string(second.KeyPEM)},
		},
		DefaultCertificate: "first",
	})
	if err != nil {
		t.Fatalf("newCertStore: %v", err)
	}
	return store, ca
}

func commonNameFor(t *testing.T, store *certStore, serverName string) string {
	t.Helper()
	cert, err := store.getCertificate(&tls.ClientHelloInfo{ServerName: serverName})
	if err != nil {
		t.Fatalf("getCertificate(%q): %v", serverName, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

func TestCertStoreSelectsBySNI(t *testing.T) {
	store, _ := testCertStore(t)

	tests := []struct {
		serverName string
		want       string
	}{
		{"mail.first.test", "mail.first.test"},
		{"mail.second.test", "mail.second.test"},
		{"alias.second.test", "mail.second.test"},
		{"MAIL.SECOND.TEST", "mail.second.test"},
		{"", "mail.first.test"},
		{"unknown.test", "mail.first.test"},
	}
	for _, tc := range tests {
		t.Run(tc.serverName, func(t *testing.T) {
			if got := commonNameFor(t, store, tc.serverName); got != tc.want {
				t.Fatalf("SNI %q served %q, want %q", tc.serverName, got, tc.want)
			}
		})
	}
}

// Without an explicit default, the first configured certificate is served.
func TestCertStoreDefaultsToFirstCertificate(t *testing.T) {
	ca, err := pki.NewCA("mailout-test")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	kp, err := ca.Issue("only.test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	store, err := newCertStore(TLSConfig{Certificates: []CertificateRef{
		{CertPEM: string(kp.CertPEM), KeyPEM: string(kp.KeyPEM)},
	}})
	if err != nil {
		t.Fatalf("newCertStore: %v", err)
	}
	if got := commonNameFor(t, store, "whatever.test"); got != "only.test" {
		t.Fatalf("got %q", got)
	}
}

func TestCertStoreRejectsBrokenKeypair(t *testing.T) {
	if _, err := newCertStore(TLSConfig{Certificates: []CertificateRef{
		{Name: "broken", CertPEM: "not a pem", KeyPEM: "neither"},
	}}); err == nil {
		t.Fatal("expected an error for a malformed keypair")
	}
}

// A wildcard certificate must answer for its subdomains.
func TestCertStoreMatchesWildcard(t *testing.T) {
	ca, err := pki.NewCA("mailout-test")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	wild, err := ca.Issue("*.wild.test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	store, err := newCertStore(TLSConfig{Certificates: []CertificateRef{
		{Name: "wild", CertPEM: string(wild.CertPEM), KeyPEM: string(wild.KeyPEM)},
	}})
	if err != nil {
		t.Fatalf("newCertStore: %v", err)
	}
	if got := commonNameFor(t, store, "smtp.wild.test"); got != "*.wild.test" {
		t.Fatalf("got %q", got)
	}
}
