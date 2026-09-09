// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// headerField is one header, kept in the order it appeared. Milters address
// headers by position, so an ordered slice is the representation that matches
// the protocol; go-message's Header, which prepends on Add, does not.
type headerField struct {
	Name  string
	Value string
}

// parsedMessage is a message split into headers and body, so that milter
// modifications can be applied and the whole thing serialized back.
type parsedMessage struct {
	Headers []headerField
	Body    []byte
}

// parseMessage splits raw RFC 5322 data. A message with no header separator is
// treated as all body, which is what an MTA would do with it.
func parseMessage(data []byte) (*parsedMessage, error) {
	msg := &parsedMessage{}
	r := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF && line == "" {
			return msg, nil
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read header: %w", err)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(msg.Headers) > 0 {
			// Continuation of a folded header: keep it verbatim.
			last := &msg.Headers[len(msg.Headers)-1]
			last.Value += "\r\n" + trimmed
			continue
		}
		name, value, found := strings.Cut(trimmed, ":")
		if !found {
			// Not a header at all — treat everything from here as body.
			rest, _ := io.ReadAll(r)
			msg.Body = append([]byte(line), rest...)
			return msg, nil
		}
		msg.Headers = append(msg.Headers, headerField{
			Name:  name,
			Value: strings.TrimPrefix(value, " "),
		})
		if err == io.EOF {
			return msg, nil
		}
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	msg.Body = body
	return msg, nil
}

// WriteHeaders writes the header block and the blank line that ends it, so a
// caller can stream a body after it instead of holding one in memory.
func (m *parsedMessage) WriteHeaders(w io.Writer) error {
	for _, f := range m.Headers {
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", f.Name, f.Value); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// Bytes serializes the message back to wire format.
func (m *parsedMessage) Bytes() []byte {
	var buf bytes.Buffer
	for _, f := range m.Headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", f.Name, f.Value)
	}
	buf.WriteString("\r\n")
	buf.Write(m.Body)
	return buf.Bytes()
}

// addHeader appends a header at the end of the header block, which is what a
// milter's SMFIR_ADDHEADER means.
func (m *parsedMessage) addHeader(name, value string) {
	m.Headers = append(m.Headers, headerField{Name: name, Value: value})
}

// insertHeader inserts at a one-based global position, per SMFIR_INSHEADER.
func (m *parsedMessage) insertHeader(index int, name, value string) {
	pos := index - 1
	if pos < 0 {
		pos = 0
	}
	if pos > len(m.Headers) {
		pos = len(m.Headers)
	}
	m.Headers = append(m.Headers, headerField{})
	copy(m.Headers[pos+1:], m.Headers[pos:])
	m.Headers[pos] = headerField{Name: name, Value: value}
}

// changeHeader replaces the index-th header with the given name (one-based per
// canonical name), per SMFIR_CHGHEADER. An empty value deletes it; an index
// past the end appends, as sendmail does.
func (m *parsedMessage) changeHeader(index int, name, value string) {
	seen := 0
	for i := range m.Headers {
		if !strings.EqualFold(m.Headers[i].Name, name) {
			continue
		}
		seen++
		if seen != index {
			continue
		}
		if value == "" {
			m.Headers = append(m.Headers[:i], m.Headers[i+1:]...)
			return
		}
		m.Headers[i].Value = value
		return
	}
	if value != "" {
		m.addHeader(name, value)
	}
}
