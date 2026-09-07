// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/d--j/go-milter"
	"github.com/emersion/go-smtp"
)

// Milter is one filter the message is passed through, over the sendmail milter
// protocol. Filters run in the declared order, each seeing the previous one's
// modifications.
type Milter struct {
	Name string `json:"name"`
	// Address is tcp://host:port or unix:///path/to/socket. A bare host:port is
	// read as TCP.
	Address string `json:"address"`
	// FailOpen lets the message through when the filter is unreachable or
	// misbehaves. Off by default: a virus scanner that is down must not turn
	// into an open relay for malware.
	FailOpen bool     `json:"failOpen,omitempty"`
	Timeout  Duration `json:"timeout,omitempty"`
}

const defaultMilterTimeout = 30 * time.Second

// network splits Address into what net.Dial expects.
func (m Milter) network() (network, address string, err error) {
	switch {
	case strings.HasPrefix(m.Address, "tcp://"):
		return "tcp", strings.TrimPrefix(m.Address, "tcp://"), nil
	case strings.HasPrefix(m.Address, "unix://"):
		return "unix", strings.TrimPrefix(m.Address, "unix://"), nil
	case strings.Contains(m.Address, "://"):
		return "", "", fmt.Errorf("unsupported scheme in %q, want tcp:// or unix://", m.Address)
	case m.Address == "":
		return "", "", fmt.Errorf("address is required")
	default:
		return "tcp", m.Address, nil
	}
}

// sessionInfo is what the milters are told about the SMTP session, through the
// standard sendmail macros.
type sessionInfo struct {
	// Hostname is the name the client announced in EHLO.
	Hostname string
	// RemoteIP and RemotePort identify the client.
	RemoteIP   string
	RemotePort uint16
	// TLSVersion and TLSCipher are empty when the session is not encrypted,
	// which cannot happen for an authenticated submission.
	TLSVersion string
	TLSCipher  string
	// AuthUser is the authenticated account, exposed as {auth_authen} so that
	// filters can apply per-account policy.
	AuthUser string
	// MTAName is this gateway's hostname.
	MTAName string
}

// milterChain applies every configured filter in order.
type milterChain struct {
	filters []milterFilter
	log     *slog.Logger
}

type milterFilter struct {
	cfg    Milter
	client *milter.Client
}

func newMilterChain(cfg *Config, log *slog.Logger) (*milterChain, error) {
	chain := &milterChain{log: log}
	for i, mc := range cfg.Milters {
		name := mc.Name
		if name == "" {
			name = fmt.Sprintf("milters[%d]", i)
		}
		network, address, err := mc.network()
		if err != nil {
			return nil, fmt.Errorf("milter %s: %w", name, err)
		}
		timeout := mc.Timeout.D()
		if timeout == 0 {
			timeout = defaultMilterTimeout
		}
		chain.filters = append(chain.filters, milterFilter{
			cfg: mc,
			client: milter.NewClient(network, address,
				milter.WithReadTimeout(timeout),
				milter.WithWriteTimeout(timeout),
				// Everything a filter may ask to change, we can apply — except
				// quarantine, which needs a spool the gateway deliberately does
				// not have.
				milter.WithAction(milter.OptAddHeader|milter.OptChangeHeader|milter.OptChangeBody|
					milter.OptAddRcpt|milter.OptRemoveRcpt|milter.OptChangeFrom|milter.OptQuarantine),
			),
		})
	}
	return chain, nil
}

// empty reports whether there is nothing to run.
func (c *milterChain) empty() bool { return len(c.filters) == 0 }

// run passes the message through every filter, applying each one's
// modifications before handing it to the next. A rejection is returned as an
// *smtp.SMTPError carrying the filter's own status code, so the submitting
// client sees why its message was refused.
func (c *milterChain) run(ctx context.Context, msg *Message, info sessionInfo) error {
	for _, f := range c.filters {
		err := c.runOne(ctx, f, msg, info)
		if err == nil {
			continue
		}
		var smtpErr *smtp.SMTPError
		if errors.As(err, &smtpErr) {
			// A verdict, not a malfunction: always honoured.
			return smtpErr
		}
		if errors.Is(err, errDiscard) {
			return err
		}
		if f.cfg.FailOpen {
			c.log.Warn("milter unavailable, letting the message through",
				"milter", f.cfg.Name, "err", err)
			continue
		}
		c.log.Error("milter unavailable, rejecting the message",
			"milter", f.cfg.Name, "err", err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 1},
			Message:      fmt.Sprintf("Filter %s unavailable, try again later", f.cfg.Name),
		}
	}
	return nil
}

func (c *milterChain) runOne(ctx context.Context, f milterFilter, msg *Message, info sessionInfo) error {
	macros := milter.NewMacroBag()
	macros.Set(milter.MacroMTAFQDN, info.MTAName)
	macros.Set(milter.MacroDaemonName, "mailout")
	macros.Set(milter.MacroIfName, info.MTAName)
	if info.AuthUser != "" {
		macros.Set(milter.MacroAuthAuthen, info.AuthUser)
		macros.Set(milter.MacroAuthType, "PLAIN")
	}
	if info.TLSVersion != "" {
		macros.Set(milter.MacroTlsVersion, info.TLSVersion)
		macros.Set(milter.MacroCipher, info.TLSCipher)
	}
	macros.Set(milter.MacroMailAddr, msg.From)

	session, err := f.client.Session(macros)
	if err != nil {
		return fmt.Errorf("open milter session: %w", err)
	}
	defer session.Close()

	family := milter.FamilyInet
	if ip := net.ParseIP(info.RemoteIP); ip != nil && ip.To4() == nil {
		family = milter.FamilyInet6
	}
	if err := check(session.Conn(info.Hostname, family, info.RemotePort, info.RemoteIP)); err != nil {
		return err
	}
	if err := check(session.Helo(info.Hostname)); err != nil {
		return err
	}
	if err := check(session.Mail(msg.From, "")); err != nil {
		return err
	}
	for _, rcpt := range msg.To {
		if err := check(session.Rcpt(rcpt, "")); err != nil {
			return err
		}
	}
	if err := check(session.DataStart()); err != nil {
		return err
	}

	parsed, err := parseMessage(msg.Data)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}
	for _, h := range parsed.Headers {
		if err := check(session.HeaderField(h.Name, h.Value, nil)); err != nil {
			return err
		}
	}
	if err := check(session.HeaderEnd()); err != nil {
		return err
	}

	// BodyReadFrom sends the body and calls End itself, so the modifications it
	// returns are the filter's final verdict.
	acts, act, err := session.BodyReadFrom(bytes.NewReader(parsed.Body))
	if err != nil {
		return fmt.Errorf("send body: %w", err)
	}
	if err := check(act, nil); err != nil {
		return err
	}

	return c.applyModifications(f, msg, parsed, acts)
}

// applyModifications folds a filter's requested changes into the message.
func (c *milterChain) applyModifications(f milterFilter, msg *Message, parsed *parsedMessage, acts []milter.ModifyAction) error {
	var replacement []byte
	replaced := false
	for _, act := range acts {
		switch act.Type {
		case milter.ActionAddHeader:
			parsed.addHeader(act.HeaderName, act.HeaderValue)
		case milter.ActionInsertHeader:
			parsed.insertHeader(int(act.HeaderIndex), act.HeaderName, act.HeaderValue)
		case milter.ActionChangeHeader:
			parsed.changeHeader(int(act.HeaderIndex), act.HeaderName, act.HeaderValue)
		case milter.ActionReplaceBody:
			// Replacement arrives as a sequence of chunks.
			replacement = append(replacement, act.Body...)
			replaced = true
		case milter.ActionChangeFrom:
			msg.From = unbracket(act.From)
		case milter.ActionAddRcpt:
			msg.To = append(msg.To, unbracket(act.Rcpt))
		case milter.ActionDelRcpt:
			msg.To = removeRecipient(msg.To, unbracket(act.Rcpt))
		case milter.ActionQuarantine:
			// There is no spool to hold a quarantined message, and silently
			// dropping it would be worse than telling the client.
			c.log.Warn("milter asked for quarantine; rejecting instead",
				"milter", f.cfg.Name, "reason", act.Reason)
			return &smtp.SMTPError{
				Code:         554,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      fmt.Sprintf("Message quarantined by %s", f.cfg.Name),
			}
		default:
			c.log.Warn("ignoring unsupported milter modification",
				"milter", f.cfg.Name, "type", act.Type)
		}
	}
	if replaced {
		parsed.Body = replacement
	}
	msg.Data = parsed.Bytes()
	if len(msg.To) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "All recipients removed by filters",
		}
	}
	return nil
}

// check turns a milter verdict into an error the SMTP layer can return.
// A nil action means "continue".
func check(act *milter.Action, err error) error {
	if err != nil {
		return err
	}
	if act == nil {
		return nil
	}
	switch {
	case act.StopProcessing():
		return smtpErrorFromAction(act)
	case act.Type == milter.ActionDiscard:
		// Accepting then dropping is what discard means; the client is told the
		// message was accepted.
		return errDiscard
	default:
		return nil
	}
}

// errDiscard signals that a filter asked for the message to be silently
// dropped. The session answers 250 and does not relay.
var errDiscard = errors.New("message discarded by filter")

func smtpErrorFromAction(act *milter.Action) *smtp.SMTPError {
	code := int(act.SMTPCode)
	if code < 400 {
		code = 550
	}
	message := strings.TrimSpace(act.SMTPReply)
	if message == "" {
		message = "Rejected by filter"
	}
	// SMTPReply carries the full "550 5.7.1 text" line; keep only the text so
	// that go-smtp does not write the code twice.
	if fields := strings.SplitN(message, " ", 2); len(fields) == 2 && len(fields[0]) == 3 {
		message = fields[1]
	}
	enhanced := smtp.EnhancedCode{5, 7, 1}
	if code < 500 {
		enhanced = smtp.EnhancedCode{4, 7, 1}
	}
	return &smtp.SMTPError{Code: code, EnhancedCode: enhanced, Message: message}
}

func unbracket(addr string) string {
	return strings.TrimSuffix(strings.TrimPrefix(addr, "<"), ">")
}

func removeRecipient(list []string, addr string) []string {
	out := list[:0]
	for _, r := range list {
		if !strings.EqualFold(r, addr) {
			out = append(out, r)
		}
	}
	return out
}
