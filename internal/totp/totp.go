// Package totp implements RFC 4226 (HOTP) and RFC 6238 (TOTP).
//
// A password manager that stores the second factor next to the first is not offering
// two-factor authentication — it is offering one factor in two formats. That is a real
// tradeoff and it is spelled out in the threat model; the feature exists because the
// alternative most people choose is SMS.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm names the HMAC hash. SHA1 remains the default because it is what
// authenticator apps and virtually every server actually implement — HMAC-SHA1's
// collision weaknesses do not apply to its use as a MAC here.
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// ErrInvalidSecret reports a secret that is not valid base32.
var ErrInvalidSecret = errors.New("totp: invalid base32 secret")

// Config is a provisioned TOTP credential.
type Config struct {
	Secret    []byte // raw bytes, already base32-decoded
	Digits    int
	Period    int // seconds
	Algorithm Algorithm
	Issuer    string
	Account   string
}

// DefaultConfig matches what every authenticator app assumes when the URI omits fields.
func DefaultConfig() Config { return Config{Digits: 6, Period: 30, Algorithm: SHA1} }

// DecodeSecret parses the base32 form a service prints, tolerating the lowercase and
// space-separated shapes people copy out of a browser.
//
// Padding is the sharp edge: RFC 4648 base32 pads to a multiple of 8 characters, but
// almost no service includes the padding. Go's StdEncoding requires it, so we add it
// back rather than telling the user their secret is malformed.
func DecodeSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s)))
	clean = strings.TrimRight(clean, "=")
	if clean == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidSecret)
	}
	if pad := len(clean) % 8; pad != 0 {
		clean += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSecret, err)
	}
	return key, nil
}

// HOTP implements RFC 4226: HMAC the 8-byte big-endian counter, then apply dynamic
// truncation.
//
// Dynamic truncation is the interesting part. The low nibble of the last byte selects a
// starting offset, and four bytes are read from there with the top bit masked off. The
// offset makes the output depend on the whole digest rather than a fixed slice; the mask
// exists because some 1990s implementations read the value as a signed integer, and a
// negative modulus is not portable.
func HOTP(secret []byte, counter uint64, digits int, alg Algorithm) (string, error) {
	if digits < 6 || digits > 10 {
		return "", fmt.Errorf("totp: digits must be 6-10, got %d", digits)
	}
	h, err := newHash(alg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(h, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

// Generate returns the code for the given moment.
func (c Config) Generate(at time.Time) (string, error) {
	if c.Period <= 0 {
		return "", fmt.Errorf("totp: period must be positive, got %d", c.Period)
	}
	return HOTP(c.Secret, uint64(at.Unix()/int64(c.Period)), c.Digits, c.Algorithm)
}

// SecondsRemaining reports how long the current code stays valid. Displaying this is not
// cosmetic: a user who copies a code with two seconds left will be told it is wrong.
func (c Config) SecondsRemaining(at time.Time) int {
	if c.Period <= 0 {
		return 0
	}
	return c.Period - int(at.Unix()%int64(c.Period))
}

// Verify checks a submitted code against the window [-skew, +skew] of time steps.
//
// The comparison is constant time and — importantly — every candidate step is evaluated
// before returning. Returning early on a match would leak, through timing, roughly how
// far the client's clock has drifted. That is a small leak, but it is free to avoid.
func (c Config) Verify(code string, at time.Time, skew int) (bool, error) {
	if skew < 0 {
		return false, fmt.Errorf("totp: skew must not be negative, got %d", skew)
	}
	step := at.Unix() / int64(c.Period)
	matched := false
	for i := -skew; i <= skew; i++ {
		candidate, err := HOTP(c.Secret, uint64(step+int64(i)), c.Digits, c.Algorithm)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(candidate), []byte(code)) {
			matched = true
		}
	}
	return matched, nil
}

// ParseURI reads an otpauth:// URI, the format behind every QR code.
//
//	otpauth://totp/Issuer:account@example.com?secret=BASE32&issuer=Issuer&digits=6&period=30
func ParseURI(raw string) (Config, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Config{}, fmt.Errorf("totp: parse uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return Config{}, fmt.Errorf("totp: expected scheme otpauth, got %q", u.Scheme)
	}
	if !strings.EqualFold(u.Host, "totp") {
		return Config{}, fmt.Errorf("totp: only totp is supported, got %q", u.Host)
	}

	c := DefaultConfig()
	q := u.Query()

	secret := q.Get("secret")
	if secret == "" {
		return Config{}, fmt.Errorf("%w: uri has no secret parameter", ErrInvalidSecret)
	}
	if c.Secret, err = DecodeSecret(secret); err != nil {
		return Config{}, err
	}

	// The label is "Issuer:Account"; the issuer query parameter wins if both are present.
	label := strings.TrimPrefix(u.Path, "/")
	if i := strings.Index(label, ":"); i >= 0 {
		c.Issuer, c.Account = label[:i], strings.TrimSpace(label[i+1:])
	} else {
		c.Account = label
	}
	if v := q.Get("issuer"); v != "" {
		c.Issuer = v
	}
	if v := q.Get("digits"); v != "" {
		if c.Digits, err = strconv.Atoi(v); err != nil {
			return Config{}, fmt.Errorf("totp: digits: %w", err)
		}
	}
	if v := q.Get("period"); v != "" {
		if c.Period, err = strconv.Atoi(v); err != nil {
			return Config{}, fmt.Errorf("totp: period: %w", err)
		}
	}
	if v := q.Get("algorithm"); v != "" {
		c.Algorithm = Algorithm(strings.ToUpper(v))
		if _, err := newHash(c.Algorithm); err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

// FromSecret builds a Config from a bare base32 secret with default parameters, which is
// what a user pastes when a site shows the "can't scan the code?" text.
func FromSecret(secret string) (Config, error) {
	c := DefaultConfig()
	key, err := DecodeSecret(secret)
	if err != nil {
		return Config{}, err
	}
	c.Secret = key
	return c, nil
}

func newHash(alg Algorithm) (func() hash.Hash, error) {
	switch alg {
	case SHA1, "":
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("totp: unsupported algorithm %q", alg)
	}
}
