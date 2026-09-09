// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// ParseAddress splits Address into what net.Dial expects. Exported so that the
// admission webhook accepts exactly what the dataplane can dial.
func (m Milter) ParseAddress() (network, address string, err error) {
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
	metrics *Metrics
}

type milterFilter struct {
	cfg    Milter
	client *milter.Client
}

func newMilterChain(cfg *Config, log *slog.Logger, metrics *Metrics) (*milterChain, error) {
	chain := &milterChain{log: log, metrics: metrics}
	for i, mc := range cfg.Milters {
		name := mc.Name
		if name == "" {
			name = fmt.Sprintf("milters[%d]", i)
		}
		network, address, err := mc.ParseAddress()
		if err != nil {
			return nil, fmt.Errorf("milter %s: %w", name, err)
		}
		timeout := mc.Timeout.D()
		if timeout == 0 {
			timeout = defaultMilterTimeout
		}
		// Resolve the name once, so logs and metrics label an unnamed filter by
		// its position rather than by an empty string.
		mc.Name = name
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
			c.metrics.milterDecided(f.cfg.Name, decisionAccept)
			continue
		}
		var smtpErr *smtp.SMTPError
		if errors.As(err, &smtpErr) {
			// A verdict, not a malfunction: always honoured.
			c.metrics.milterDecided(f.cfg.Name, decisionReject)
			return smtpErr
		}
		if errors.Is(err, errDiscard) {
			c.metrics.milterDecided(f.cfg.Name, decisionDiscard)
			return err
		}
		// Counted the same whether the message then goes through or not: what
		// this measures is the filter being down, and fail-open is precisely
		// the case where nothing else would show it.
		c.metrics.milterDecided(f.cfg.Name, decisionUnavailable)
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

	// Only the header block is parsed, and it is bounded: the body goes to the
	// filter straight from the spool. A milter hands headers and body over
	// separately, and BodyReadFrom takes a reader, so nothing here needs the
	// message in memory — which is what keeps a 25 MiB submission from costing
	// 25 MiB of heap per filter in the chain.
	header, terminated, err := msg.Body.headerBlock()
	if err != nil {
		return err
	}
	var parsed *parsedMessage
	if terminated {
		if parsed, err = parseMessage(header); err != nil {
			return fmt.Errorf("parse message: %w", err)
		}
		for _, h := range parsed.Headers {
			if err := check(session.HeaderField(h.Name, h.Value, nil)); err != nil {
				return err
			}
		}
	} else {
		// No end of header block within the bound. parseMessage would call the
		// whole thing a body, and so does this: the filter sees no headers and
		// the entire message as content.
		parsed = &parsedMessage{}
		header = nil
	}
	if err := check(session.HeaderEnd()); err != nil {
		return err
	}

	body, err := msg.Body.ReaderAt(int64(len(header)))
	if err != nil {
		return err
	}
	// BodyReadFrom sends the body and calls End itself, so the modifications it
	// returns are the filter's final verdict.
	acts, act, err := session.BodyReadFrom(body)
	if err != nil {
		return fmt.Errorf("send body: %w", err)
	}
	if err := check(act, nil); err != nil {
		return err
	}

	return c.applyModifications(f, msg, parsed, int64(len(header)), acts)
}

// applyModifications folds a filter's requested changes into the message.
func (c *milterChain) applyModifications(f milterFilter, msg *Message, parsed *parsedMessage,
	headerLen int64, acts []milter.ModifyAction) error {
	// A replaced body is the filter's own output and can be any size, so it
	// goes to a spool of its own rather than growing on the heap.
	var replacement *spool
	defer func() {
		if replacement != nil {
			_ = replacement.Close()
		}
	}()
	headersChanged := false
	for _, act := range acts {
		switch act.Type {
		case milter.ActionAddHeader:
			parsed.addHeader(act.HeaderName, act.HeaderValue)
			headersChanged = true
		case milter.ActionInsertHeader:
			parsed.insertHeader(int(act.HeaderIndex), act.HeaderName, act.HeaderValue)
			headersChanged = true
		case milter.ActionChangeHeader:
			parsed.changeHeader(int(act.HeaderIndex), act.HeaderName, act.HeaderValue)
			headersChanged = true
		case milter.ActionReplaceBody:
			// Replacement arrives as a sequence of chunks.
			if replacement == nil {
				replacement = msg.Body.sibling()
			}
			if _, err := replacement.Write(act.Body); err != nil {
				return err
			}
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
	if headersChanged || replacement != nil {
		if err := rewriteBody(msg, parsed, headerLen, replacement); err != nil {
			return err
		}
	}
	// Otherwise the message is untouched and stays exactly where it is: a
	// filter that only accepts — the common case — costs no copy at all.
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

// rewriteBody rebuilds the message from the modified headers and either the
// filter's replacement body or the original one, streaming both.
//
// The result goes to a new spool rather than over the existing one: the source
// is still being read from while the destination is written, and truncating in
// place would pull the ground out from under it.
func rewriteBody(msg *Message, parsed *parsedMessage, headerLen int64, replacement *spool) error {
	out := msg.Body.sibling()
	if err := parsed.WriteHeaders(out); err != nil {
		_ = out.Close()
		return err
	}

	var source io.Reader
	var err error
	if replacement != nil {
		source, err = replacement.Reader()
	} else {
		source, err = msg.Body.ReaderAt(headerLen)
	}
	if err != nil {
		_ = out.Close()
		return err
	}
	if _, err := io.Copy(out, source); err != nil {
		_ = out.Close()
		return err
	}

	_ = msg.Body.Close()
	msg.Body = out
	return nil
}
