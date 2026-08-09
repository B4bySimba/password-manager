// Package hibp checks passwords against the Have I Been Pwned breach corpus using the
// k-anonymity range API.
//
// The protocol is the whole reason this is safe to ship in a password manager: the
// client sends the first five hex characters of the password's SHA-1 and receives every
// suffix sharing that prefix - roughly 800 hashes. The comparison happens locally. The
// server learns a bucket containing about one 1,048,576th of the hash space and never
// sees the password, the full hash, or which of the returned suffixes matched.
//
// It is still a network request that only happens because the user has a specific
// password, so it is OFF by default and must be enabled explicitly.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RangeURL is the k-anonymity endpoint.
const RangeURL = "https://api.pwnedpasswords.com/range/"

// ErrDisabled is returned when a check is attempted without opting in. Returning an
// error rather than silently reporting "not breached" matters: a caller must never
// mistake "we did not look" for "we looked and it was clean".
var ErrDisabled = errors.New("hibp: breach checking is disabled; enable it explicitly")

// Doer is the subset of *http.Client this package needs. It exists so tests can supply
// a canned corpus and the suite never touches the network.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Checker performs range lookups.
type Checker struct {
	Client  Doer
	BaseURL string
	Enabled bool
	Timeout time.Duration
}

// New returns a checker that is disabled until Enabled is set.
func New(enabled bool) *Checker {
	return &Checker{
		Client:  &http.Client{Timeout: 10 * time.Second},
		BaseURL: RangeURL,
		Enabled: enabled,
		Timeout: 10 * time.Second,
	}
}

// Result reports what the corpus knows about a password.
type Result struct {
	Breached bool
	Count    int    // times seen across known breaches
	Prefix   string // the five characters that were sent - printable, so the privacy claim is checkable
	Bucket   int    // suffixes returned, i.e. the size of the anonymity set
}

// Check looks up a password. The password itself never leaves this function.
func (c *Checker) Check(ctx context.Context, password string) (Result, error) {
	if !c.Enabled {
		return Result{}, ErrDisabled
	}
	prefix, suffix := HashPrefix(password)

	base := c.BaseURL
	if base == "" {
		base = RangeURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+prefix, nil)
	if err != nil {
		return Result{}, fmt.Errorf("hibp: build request: %w", err)
	}
	// Padding makes every response a similar size, so an observer who can see response
	// lengths cannot narrow down which bucket was requested.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "govault-password-manager")

	resp, err := c.Client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("hibp: range request for %s: %w", prefix, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("hibp: range request for %s returned %s", prefix, resp.Status)
	}
	count, bucket, err := scanRange(resp.Body, suffix)
	if err != nil {
		return Result{}, err
	}
	return Result{Breached: count > 0, Count: count, Prefix: prefix, Bucket: bucket}, nil
}

// HashPrefix returns the 5-character prefix that is sent and the 35-character suffix
// that is kept. Exported so a caller - or a suspicious user - can verify by inspection
// exactly what would go over the wire.
func HashPrefix(password string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	return full[:5], full[5:]
}

// scanRange walks the "SUFFIX:COUNT" lines.
//
// Every line is read even after a match, and the comparison is length-independent, so
// the time taken does not depend on where in the response the password appeared. The
// padding entries the API inserts have a count of 0 and are skipped.
func scanRange(body io.Reader, wantSuffix string) (count, bucket int, err error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sep := strings.IndexByte(line, ':')
		if sep < 0 {
			return 0, 0, fmt.Errorf("hibp: malformed range line %q", line)
		}
		suffix, countStr := line[:sep], line[sep+1:]
		n, convErr := strconv.Atoi(strings.TrimSpace(countStr))
		if convErr != nil {
			return 0, 0, fmt.Errorf("hibp: malformed count in %q: %w", line, convErr)
		}
		if n > 0 {
			bucket++
		}
		if strings.EqualFold(suffix, wantSuffix) {
			count = n
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("hibp: read range response: %w", err)
	}
	return count, bucket, nil
}
