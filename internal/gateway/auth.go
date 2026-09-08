// Copyright (c) 2026 Damien Daly. All rights reserved.

package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the cost used for every password the operator generates. It is
// also the cost the dataplane pays on each authentication, so it trades login
// latency against offline-cracking resistance.
const BcryptCost = 12

// MinBcryptCost and MaxBcryptCost bound what the gateway will serve.
//
// This is not tuning, it is a denial of service control. The hash reaches the
// shared configuration from a Secret in the tenant's own namespace, so the cost
// encoded in it is attacker-chosen: a $2a$31$ hash makes every AUTH attempt on
// that username burn hours of CPU inside the connection handler, for every
// replica, and AUTH is pre-authentication. The band is wide enough to survive
// a future change of BcryptCost without regenerating every password, and
// narrow enough that no cost in it can be weaponised.
const (
	MinBcryptCost = 10
	MaxBcryptCost = 14
)

// UsableHash reports whether a stored hash is one the gateway will authenticate
// against: parseable by bcrypt, and of a cost inside the band.
func UsableHash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	return err == nil && cost >= MinBcryptCost && cost <= MaxBcryptCost
}

// PasswordBytes is the entropy of a generated password, before base64 encoding.
const PasswordBytes = 24

var (
	errAuthFailed      = errors.New("authentication failed")
	errAccountDisabled = errors.New("account is disabled")
)

// HashPassword returns the bcrypt hash stored in Kubernetes and served to the
// dataplane. The cleartext is never persisted anywhere but the application's
// own Secret.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}

// GeneratePassword returns a new random password, URL-safe so that it survives
// being carried in environment variables and connection strings.
func GeneratePassword() (string, error) {
	buf := make([]byte, PasswordBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// accountStore resolves credentials to accounts. It is immutable: a
// configuration change builds a new one.
type accountStore struct {
	byUsername map[string]*Account
	// dummyHash is compared against when the username is unknown, so that an
	// unknown user costs the same as a wrong password.
	dummyHash string
}

// dummyPassword is never a valid credential; only the cost of comparing
// against its hash matters.
const dummyPassword = "mailout-timing-equalizer"

func newAccountStore(accounts []Account) *accountStore {
	s := &accountStore{byUsername: make(map[string]*Account, len(accounts))}
	for i := range accounts {
		acct := accounts[i]
		s.byUsername[acct.Username] = &acct
	}
	// Cost 4 would be cheaper but would not equalize anything; use the real
	// cost so the timings actually match.
	//
	// A dropped error here used to leave dummyHash empty, which turned the
	// equalization below into a no-op: an unknown username then answered in
	// nanoseconds against ~180ms for a known one — a perfect account
	// enumeration oracle. dummyPassword is a compile-time constant, so a
	// failure here cannot depend on input: it can only mean the process is
	// unable to compute bcrypt at all, and then refusing to serve is the only
	// honest answer.
	h, err := bcrypt.GenerateFromPassword([]byte(dummyPassword), BcryptCost)
	if err != nil {
		panic(fmt.Sprintf("cannot hash the timing equalizer, bcrypt is unusable: %v", err))
	}
	s.dummyHash = string(h)
	return s
}

// authenticate validates a username/password pair. Usernames are compared
// verbatim: they are provisioned by the operator, not typed by humans.
func (s *accountStore) authenticate(username, password string) (*Account, error) {
	acct, ok := s.byUsername[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword([]byte(s.dummyHash), []byte(password))
		return nil, errAuthFailed
	}
	if err := bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(password)); err != nil {
		return nil, errAuthFailed
	}
	if acct.Disabled {
		return nil, errAccountDisabled
	}
	return acct, nil
}

// label returns the username if it names a configured account, and the
// unknownAccount placeholder otherwise. It exists so that a metric label can
// never be dictated by whoever is connecting.
func (s *accountStore) label(username string) string {
	if _, ok := s.byUsername[username]; ok {
		return username
	}
	return unknownAccount
}

// loginAuthenticator validates the credentials collected by the LOGIN
// mechanism.
type loginAuthenticator func(username, password string) error

// loginServer implements the obsolete-but-widespread SASL LOGIN mechanism,
// which go-sasl only provides on the client side. Several mail libraries
// (notably older .NET and PHP clients) offer nothing else.
type loginServer struct {
	authenticate loginAuthenticator
	username     string
	state        int
}

func newLoginServer(authenticate loginAuthenticator) *loginServer {
	return &loginServer{authenticate: authenticate}
}

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.state {
	case 0:
		s.state++
		// A client may send the username as an initial response.
		if len(response) > 0 {
			s.username = string(response)
			s.state++
			return []byte("Password:"), false, nil
		}
		return []byte("Username:"), false, nil
	case 1:
		s.state++
		s.username = string(response)
		return []byte("Password:"), false, nil
	case 2:
		s.state++
		if err := s.authenticate(s.username, string(response)); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	default:
		return nil, false, errAuthFailed
	}
}
