// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package gateway

import (
	"strings"
	"testing"
)

const rawMessage = "Received: from a\r\n" +
	"From: app@example.test\r\n" +
	"To: dest@example.test\r\n" +
	"Subject: hello\r\n" +
	"\r\n" +
	"body line 1\r\nbody line 2\r\n"

func TestParseMessageRoundTrip(t *testing.T) {
	msg, err := parseMessage([]byte(rawMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if len(msg.Headers) != 4 {
		t.Fatalf("got %d headers: %+v", len(msg.Headers), msg.Headers)
	}
	if msg.Headers[0].Name != "Received" || msg.Headers[3].Value != "hello" {
		t.Fatalf("headers = %+v", msg.Headers)
	}
	if string(msg.Body) != "body line 1\r\nbody line 2\r\n" {
		t.Fatalf("body = %q", msg.Body)
	}
	if got := string(msg.Bytes()); got != rawMessage {
		t.Fatalf("round trip changed the message:\n%q\nwant\n%q", got, rawMessage)
	}
}

func TestParseMessageFoldedHeader(t *testing.T) {
	raw := "Subject: a very\r\n long subject\r\nTo: dest@example.test\r\n\r\nbody\r\n"
	msg, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if len(msg.Headers) != 2 {
		t.Fatalf("got %d headers: %+v", len(msg.Headers), msg.Headers)
	}
	if msg.Headers[0].Value != "a very\r\n long subject" {
		t.Fatalf("folded value = %q", msg.Headers[0].Value)
	}
	if got := string(msg.Bytes()); got != raw {
		t.Fatalf("round trip = %q", got)
	}
}

func TestMessageHeaderModifications(t *testing.T) {
	msg, err := parseMessage([]byte(rawMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}

	msg.addHeader("X-Virus-Scanned", "clamav")
	if last := msg.Headers[len(msg.Headers)-1]; last.Name != "X-Virus-Scanned" {
		t.Fatalf("addHeader did not append: %+v", msg.Headers)
	}

	msg.insertHeader(1, "X-First", "yes")
	if msg.Headers[0].Name != "X-First" {
		t.Fatalf("insertHeader(1) put it at %+v", msg.Headers[0])
	}

	msg.changeHeader(1, "Subject", "changed")
	if got := headerValue(msg, "Subject"); got != "changed" {
		t.Fatalf("Subject = %q", got)
	}

	msg.changeHeader(1, "To", "")
	if headerValue(msg, "To") != "" {
		t.Fatal("To should have been deleted")
	}

	// An index past the end appends, like sendmail does.
	msg.changeHeader(9, "X-New", "appended")
	if got := headerValue(msg, "X-New"); got != "appended" {
		t.Fatalf("X-New = %q", got)
	}
}

func headerValue(m *parsedMessage, name string) string {
	for _, f := range m.Headers {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}
