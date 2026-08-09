// Package pwgen generates passwords and estimates how much a password is worth.
package pwgen

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Character classes. Ambiguous glyphs are separated out so they can be excluded: a
// password nobody can read off a screen gets written down, which is a worse outcome than
// the ~0.2 bits per character the exclusion costs.
const (
	Lower     = "abcdefghijkmnopqrstuvwxyz" // no l
	Upper     = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // no I, O
	Digits    = "23456789"                  // no 0, 1
	Symbols   = "!@#$%^&*()-_=+[]{};:,.?/"
	Ambiguous = "lIO01"
)

// ErrImpossible reports a request that cannot be satisfied, e.g. requiring four
// character classes in a three-character password.
var ErrImpossible = errors.New("pwgen: impossible generation request")

// Options controls password generation.
type Options struct {
	Length         int
	UseLower       bool
	UseUpper       bool
	UseDigits      bool
	UseSymbols     bool
	IncludeAmbig   bool // add back l, I, O, 0, 1
	RequireEach    bool // guarantee at least one character from every enabled class
	ExcludeCharSet string
}

// DefaultOptions is 20 characters from all four classes: ~124 bits, comfortably beyond
// what an offline attacker will ever grind through, and still selectable with a mouse.
func DefaultOptions() Options {
	return Options{Length: 20, UseLower: true, UseUpper: true, UseDigits: true, UseSymbols: true, RequireEach: true}
}

// Generate returns a random password.
//
// Two details that are easy to get wrong and are the reason this is not three lines:
//
// Selection uses rejection sampling, not `rand % len(alphabet)`. Modulo folds the 256
// byte values unevenly onto an alphabet whose size does not divide 256, making some
// characters measurably more likely. For a 24-symbol set that is a real, exploitable
// skew in the search space.
//
// RequireEach places one character per class and then shuffles the whole string. Placing
// the guaranteed characters at fixed positions - the common shortcut - means position 0
// is always lowercase, which is information an attacker gets for free.
func Generate(o Options) (string, error) {
	if o.Length <= 0 {
		return "", fmt.Errorf("%w: length must be positive, got %d", ErrImpossible, o.Length)
	}

	classes, err := o.classes()
	if err != nil {
		return "", err
	}
	if o.RequireEach && o.Length < len(classes) {
		return "", fmt.Errorf("%w: length %d cannot contain one character from each of %d classes",
			ErrImpossible, o.Length, len(classes))
	}

	alphabet := strings.Join(classes, "")
	out := make([]byte, 0, o.Length)

	if o.RequireEach {
		for _, c := range classes {
			ch, err := pick(c)
			if err != nil {
				return "", err
			}
			out = append(out, ch)
		}
	}
	for len(out) < o.Length {
		ch, err := pick(alphabet)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// classes returns the enabled, filtered character sets.
func (o Options) classes() ([]string, error) {
	add := func(base, ambig string) string {
		s := base
		if o.IncludeAmbig {
			for _, r := range ambig {
				if !strings.ContainsRune(s, r) {
					s += string(r)
				}
			}
		}
		return filter(s, o.ExcludeCharSet)
	}

	var classes []string
	if o.UseLower {
		classes = append(classes, add(Lower, "l"))
	}
	if o.UseUpper {
		classes = append(classes, add(Upper, "IO"))
	}
	if o.UseDigits {
		classes = append(classes, add(Digits, "01"))
	}
	if o.UseSymbols {
		classes = append(classes, filter(Symbols, o.ExcludeCharSet))
	}

	if len(classes) == 0 {
		return nil, fmt.Errorf("%w: no character classes enabled", ErrImpossible)
	}
	for i, c := range classes {
		if c == "" {
			return nil, fmt.Errorf("%w: class %d was emptied by the exclusion set", ErrImpossible, i)
		}
	}
	return classes, nil
}

func filter(s, exclude string) string {
	if exclude == "" {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !strings.ContainsRune(exclude, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pick returns one uniformly random character from alphabet using rejection sampling.
func pick(alphabet string) (byte, error) {
	n := len(alphabet)
	if n == 0 {
		return 0, fmt.Errorf("%w: empty alphabet", ErrImpossible)
	}
	i, err := uniform(uint32(n))
	if err != nil {
		return 0, err
	}
	return alphabet[i], nil
}

// uniform returns a uniformly random value in [0,n) with no modulo bias.
//
// The trick: reject any draw at or above the largest multiple of n that fits in the
// range. What remains divides evenly, so the modulo is exact. The expected number of
// draws is under 2 for any n, and the loop has no worst-case bound only in the sense
// that a fair coin has no bound on runs of heads.
func uniform(n uint32) (uint32, error) {
	if n == 0 {
		return 0, fmt.Errorf("%w: uniform(0)", ErrImpossible)
	}
	limit := math.MaxUint32 - (math.MaxUint32 % uint64(n)) - 1
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("pwgen: read randomness: %w", err)
		}
		v := binary.BigEndian.Uint32(buf[:])
		if uint64(v) <= limit {
			return v % n, nil
		}
	}
}

// shuffle is Fisher-Yates driven by the CSPRNG. Using math/rand here would make the
// permutation predictable from a known seed and undo the careful selection above.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := uniform(uint32(i + 1))
		if err != nil {
			return err
		}
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// Passphrase returns `words` words joined by sep, optionally capitalised and with a
// digit appended.
//
// Entropy is words × log2(len(wordlist)) - and *only* that. The capitalisation and the
// trailing digit add a handful of bits at most, because an attacker knows the generator's
// rules. They exist to satisfy composition requirements, not to add security, and
// Entropy() reports them at their true worth rather than the flattering one.
func Passphrase(words int, sep string, capitalize, appendDigit bool) (string, error) {
	if words <= 0 {
		return "", fmt.Errorf("%w: word count must be positive, got %d", ErrImpossible, words)
	}
	parts := make([]string, words)
	for i := range parts {
		idx, err := uniform(uint32(len(Wordlist)))
		if err != nil {
			return "", err
		}
		w := Wordlist[idx]
		if capitalize {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		parts[i] = w
	}
	out := strings.Join(parts, sep)
	if appendDigit {
		d, err := uniform(10)
		if err != nil {
			return "", err
		}
		out += fmt.Sprintf("%d", d)
	}
	return out, nil
}

// PassphraseEntropy reports the true entropy of a Passphrase result, in bits.
func PassphraseEntropy(words int, appendDigit bool) float64 {
	bits := float64(words) * math.Log2(float64(len(Wordlist)))
	if appendDigit {
		bits += math.Log2(10)
	}
	return bits
}

// GeneratedEntropy reports the entropy of a Generate result, in bits.
//
// This is length × log2(alphabet), which is correct only because the password is
// machine-generated and uniform. Do not apply it to a human-chosen password - that is
// what Estimate is for, and the gap between the two numbers is usually enormous.
func GeneratedEntropy(o Options) float64 {
	classes, err := o.classes()
	if err != nil {
		return 0
	}
	return float64(o.Length) * math.Log2(float64(len(strings.Join(classes, ""))))
}
