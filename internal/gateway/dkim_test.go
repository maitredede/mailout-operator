// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// dkimTestKey generates a key and the DNS record a verifier would look up.
func dkimTestKey(t *testing.T, algorithm, domain, selector string) (DKIMKey, func(string) ([]string, error)) {
	t.Helper()
	generated, err := GenerateDKIMKey(algorithm, domain, selector)
	if err != nil {
		t.Fatalf("GenerateDKIMKey: %v", err)
	}
	lookup := func(name string) ([]string, error) {
		if name != generated.DNSRecordName {
			return nil, fmt.Errorf("unexpected lookup for %q", name)
		}
		return []string{generated.DNSRecordValue}, nil
	}
	return DKIMKey{
		Domain:        domain,
		Selector:      selector,
		PrivateKeyPEM: generated.PrivateKeyPEM,
	}, lookup
}

// signedMessage signs msg with the given keys, on behalf of an account allowed
// to send from allowedSenders. The policy is not optional: a key on the gateway
// is not authority to use it.
func signedMessage(t *testing.T, keys []DKIMKey, msg *Message, allowedSenders ...string) *Message {
	t.Helper()
	signer, err := newDKIMSigner(keys, testLogger(), nil)
	if err != nil {
		t.Fatalf("newDKIMSigner: %v", err)
	}
	if err := signer.sign(msg, newSenderPolicy(allowedSenders)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return msg
}

func TestDKIMSignatureVerifies(t *testing.T) {
	for _, algorithm := range []string{"rsa", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			key, lookup := dkimTestKey(t, algorithm, "example.test", "mail")
			msg := signedMessage(t, []DKIMKey{key}, &Message{
				From: "app@example.test",
				To:   []string{"dest@elsewhere.test"},
				Body: bodyOf(t, []byte("From: app@example.test\r\nSubject: signed\r\n\r\nbody\r\n")),
			}, "*@example.test")

			if !strings.Contains(string(bytesOf(t, msg)), "DKIM-Signature:") {
				t.Fatalf("no signature added:\n%s", bytesOf(t, msg))
			}
			verifications, err := dkim.VerifyWithOptions(bytes.NewReader(bytesOf(t, msg)),
				&dkim.VerifyOptions{LookupTXT: lookup})
			if err != nil {
				t.Fatalf("VerifyWithOptions: %v", err)
			}
			if len(verifications) != 1 {
				t.Fatalf("got %d verifications", len(verifications))
			}
			if verifications[0].Err != nil {
				t.Fatalf("signature does not verify: %v", verifications[0].Err)
			}
			if verifications[0].Domain != "example.test" {
				t.Fatalf("signed as %q", verifications[0].Domain)
			}
		})
	}
}

// Signing under a domain we do not own would break DMARC alignment, so a sender
// with no matching key is left unsigned rather than mis-signed.
func TestDKIMLeavesUnknownDomainUnsigned(t *testing.T) {
	key, _ := dkimTestKey(t, "rsa", "example.test", "mail")
	msg := signedMessage(t, []DKIMKey{key}, &Message{
		From: "app@other.test",
		Body: bodyOf(t, []byte("From: app@other.test\r\nSubject: hi\r\n\r\nbody\r\n")),
	}, "*@other.test")
	if strings.Contains(string(bytesOf(t, msg)), "DKIM-Signature:") {
		t.Fatalf("message was signed under the wrong domain:\n%s", bytesOf(t, msg))
	}
}

// A submission with an empty envelope sender must still be signed, using the
// From header.
func TestDKIMFallsBackToFromHeader(t *testing.T) {
	key, lookup := dkimTestKey(t, "rsa", "example.test", "mail")
	msg := signedMessage(t, []DKIMKey{key}, &Message{
		From: "",
		Body: bodyOf(t, []byte("From: Application <app@example.test>\r\nSubject: hi\r\n\r\nbody\r\n")),
	}, "*@example.test")
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(bytesOf(t, msg)),
		&dkim.VerifyOptions{LookupTXT: lookup})
	if err != nil || len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("signature missing or invalid: %v %+v", err, verifications)
	}
}

func TestDKIMRejectsDuplicateDomain(t *testing.T) {
	first, _ := dkimTestKey(t, "rsa", "example.test", "a")
	second, _ := dkimTestKey(t, "rsa", "example.test", "b")
	if _, err := newDKIMSigner([]DKIMKey{first, second}, testLogger(), nil); err == nil {
		t.Fatal("expected two keys for one domain to be rejected")
	}
}

func TestDomainOf(t *testing.T) {
	tests := map[string]string{
		"app@example.test":               "example.test",
		"Application <app@Example.Test>": "example.test",
		"<app@example.test>":             "example.test",
		"":                               "",
		"not-an-address":                 "",
	}
	for input, want := range tests {
		if got := domainOf(input); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGeneratedDKIMRecordShape(t *testing.T) {
	generated, err := GenerateDKIMKey("rsa", "example.test", "mail")
	if err != nil {
		t.Fatalf("GenerateDKIMKey: %v", err)
	}
	if generated.DNSRecordName != "mail._domainkey.example.test" {
		t.Fatalf("record name = %q", generated.DNSRecordName)
	}
	if !strings.HasPrefix(generated.DNSRecordValue, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("record value = %q", generated.DNSRecordValue)
	}
}

// The core of the tenant isolation: a key existing on the gateway is not
// authority to use it. Without this, any account could have any of the
// gateway's domains signed by claiming to send from it — one tenant vouching
// for another.
func TestDKIMRefusesToSignAnUnauthorizedDomain(t *testing.T) {
	key, lookup := dkimTestKey(t, "rsa", "victim.test", "mail")
	msg := signedMessage(t, []DKIMKey{key}, &Message{
		From:    "attacker@victim.test",
		Account: "tenant-a.app",
		Body:    bodyOf(t, []byte("From: attacker@victim.test\r\nSubject: spoofed\r\n\r\nbody\r\n")),
	}, "*@attacker.test") // allowed on its own domain only

	if strings.Contains(string(bytesOf(t, msg)), "DKIM-Signature:") {
		t.Fatalf("signed a domain the account may not send from:\n%s", bytesOf(t, msg))
	}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(bytesOf(t, msg)),
		&dkim.VerifyOptions{LookupTXT: lookup})
	if err == nil && len(verifications) > 0 {
		t.Fatalf("a signature was produced for victim.test: %+v", verifications)
	}
}

// An account that declared nothing sends freely but is never signed: declaring
// a sender is what earns a signature.
func TestDKIMSignsNothingWithoutADeclaredSender(t *testing.T) {
	key, _ := dkimTestKey(t, "rsa", "example.test", "mail")
	msg := signedMessage(t, []DKIMKey{key}, &Message{
		From: "app@example.test",
		Body: bodyOf(t, []byte("From: app@example.test\r\nSubject: hi\r\n\r\nbody\r\n")),
	})
	if strings.Contains(string(bytesOf(t, msg)), "DKIM-Signature:") {
		t.Fatalf("an account with no allowedSenders got its mail signed:\n%s", bytesOf(t, msg))
	}
}

// RFC 8301 deprecates 1024-bit RSA for DKIM. A factored key does not merely
// weaken a signature: it lets whoever factored it mint mail that is DKIM-valid
// and DMARC-aligned for the domain. This used to load and sign without a word,
// and the PKCS#1 branch returned the key without looking at it at all.
func TestWeakRSAKeyIsRefused(t *testing.T) {
	for name, bits := range map[string]int{"1024 bits": 1024, "2048 bits": 2048} {
		t.Run(name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			for encoding, pemBytes := range map[string][]byte{
				"PKCS#8": pkcs8PEM(t, key),
				"PKCS#1": pkcs1PEM(t, key),
			} {
				t.Run(encoding, func(t *testing.T) {
					_, err := loadDKIMPrivateKey(DKIMKey{PrivateKeyPEM: string(pemBytes)})
					switch {
					case bits < minRSABits && err == nil:
						t.Errorf("a %d bit key was accepted", bits)
					case bits >= minRSABits && err != nil:
						t.Errorf("a %d bit key was refused: %v", bits, err)
					}
				})
			}
		})
	}
}

func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pkcs1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
