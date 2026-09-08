// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// Each of these is a way found by an adversarial review to get a From past the
// sender policy. They all worked the same way: make the check find nothing to
// look at, and it returned nil.
func TestHeaderFromBypassesAreRefused(t *testing.T) {
	policy := newSenderPolicy([]string{"*@allowed.test"})

	for name, tc := range map[string]struct {
		message string
		wantErr bool
	}{
		"allowed sender": {
			"From: ok@allowed.test\r\nSubject: hi\r\n\r\nbody\r\n", false,
		},
		"refused sender": {
			"From: ceo@victim.test\r\nSubject: hi\r\n\r\nbody\r\n", true,
		},
		// The worst one: the first From satisfies the policy, the second does
		// not, and the signer covered both.
		"two From headers": {
			"From: ok@allowed.test\r\nFrom: ceo@victim.test\r\nSubject: hi\r\n\r\nbody\r\n", true,
		},
		"two From headers, refused one first": {
			"From: ceo@victim.test\r\nFrom: ok@allowed.test\r\nSubject: hi\r\n\r\nbody\r\n", true,
		},
		// Parsed as a header named "From ", which matched nothing.
		"space before the colon": {
			"From : ceo@victim.test\r\nSubject: hi\r\n\r\nbody\r\n", true,
		},
		// No colon on the first line makes the whole message body, so there was
		// no header to check.
		"first line is not a header": {
			"not a header at all\r\nFrom: ceo@victim.test\r\n\r\nbody\r\n", true,
		},
		"no From at all": {
			"Subject: hi\r\n\r\nbody\r\n", true,
		},
		// No blank line: the header block never ends, so nothing could be
		// concluded from it.
		"unterminated header block": {
			"Subject: hi\r\nFrom: ceo@victim.test\r\n", true,
		},
		"folded From is still one header": {
			"From: Application\r\n <ok@allowed.test>\r\nSubject: hi\r\n\r\nbody\r\n", false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkHeaderFrom(bodyOf(t, []byte(tc.message)), policy)
			if tc.wantErr && err == nil {
				t.Errorf("the message was accepted:\n%s", tc.message)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("a legitimate message was refused: %v", err)
			}
			// Whatever the reason, a refusal must be permanent: retrying an
			// unparsable message changes nothing.
			if err != nil {
				var smtpErr *smtp.SMTPError
				if !errors.As(err, &smtpErr) || smtpErr.Code < 500 {
					t.Errorf("refusal should be a 5xx, got %v", err)
				}
			}
		})
	}
}

// End to end: a second From must not reach the upstream at all, which is what
// makes the DKIM half of the attack moot as well.
func TestSecondFromHeaderNeverReachesTheUpstream(t *testing.T) {
	gw := newTestGateway(t, func(cfg *Config) {
		cfg.Accounts[0].AllowedSenders = []string{"*@example.test"}
	})

	c := gw.dialSubmission(t)
	if err := c.Auth(sasl.NewPlainClient("", testAccount, testPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	body := "From: app@example.test\r\nFrom: ceo@victim.test\r\nSubject: forged\r\n\r\nbody\r\n"
	err := c.SendMail("app@example.test", []string{"dest@example.test"}, strings.NewReader(body))
	if err == nil {
		t.Fatal("a message with two From headers was relayed")
	}
	if received := gw.upstream.received(); len(received) != 0 {
		t.Errorf("the upstream received %d messages, want none", len(received))
	}
}

// Oversigning is deliberately not used: the library signs it but cannot verify
// it. This test states that choice, so that turning it on is a deliberate act
// and not an accident — and so that the reason is next to the assertion.
func TestHeaderKeysAreLeftToTheLibrary(t *testing.T) {
	if got := headerKeysFor(nil); got != nil {
		t.Errorf("headerKeysFor(nil) = %v, want nil: go-msgauth cannot verify an "+
			"oversigned signature it produced itself, so the default set is the library's", got)
	}
	declared := []string{"From", "Subject"}
	if got := headerKeysFor(declared); len(got) != 2 {
		t.Errorf("headerKeysFor(%v) = %v, want the declared set", declared, got)
	}
}
