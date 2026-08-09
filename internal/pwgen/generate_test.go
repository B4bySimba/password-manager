package pwgen

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestGenerateRespectsLength(t *testing.T) {
	for _, n := range []int{4, 8, 20, 64, 128} {
		o := DefaultOptions()
		o.Length = n
		p, err := Generate(o)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if len(p) != n {
			t.Errorf("asked for %d characters, got %d", n, len(p))
		}
	}
}

func TestGenerateHonoursEveryClassCombination(t *testing.T) {
	cases := []struct {
		name    string
		options Options
		forbid  string
	}{
		{"no symbols", Options{Length: 40, UseLower: true, UseUpper: true, UseDigits: true}, Symbols},
		{"no digits", Options{Length: 40, UseLower: true, UseUpper: true, UseSymbols: true}, Digits},
		{"lowercase only", Options{Length: 40, UseLower: true}, Upper + Digits + Symbols},
		{"digits only", Options{Length: 40, UseDigits: true}, Lower + Upper + Symbols},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Generate(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if i := strings.IndexAny(p, tc.forbid); i >= 0 {
				t.Fatalf("%q contains the excluded character %q at %d", p, p[i], i)
			}
		})
	}
}

func TestAmbiguousCharactersAreExcludedByDefault(t *testing.T) {
	o := DefaultOptions()
	o.Length = 200
	p, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Ambiguous {
		if strings.ContainsRune(p, r) {
			t.Errorf("default generation produced the lookalike character %q", r)
		}
	}
}

func TestIncludeAmbiguousAddsThemBack(t *testing.T) {
	o := DefaultOptions()
	o.Length = 4000
	o.IncludeAmbig = true
	p, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	// With 4000 characters, missing any of the five would mean they are not in the
	// alphabet at all rather than being unlucky.
	for _, r := range "lIO01" {
		if !strings.ContainsRune(p, r) {
			t.Errorf("--ambiguous did not add %q back to the alphabet", r)
		}
	}
}

// RequireEach must not be implemented by fixing positions, which would make position 0
// always lowercase and hand an attacker free information.
func TestRequireEachDoesNotFixPositions(t *testing.T) {
	o := DefaultOptions()
	o.Length = 4

	seenAtZero := map[string]bool{}
	for i := 0; i < 400; i++ {
		p, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if !hasAll(p) {
			t.Fatalf("%q is missing a required class", p)
		}
		seenAtZero[classOf(p[0])] = true
	}
	if len(seenAtZero) < 4 {
		t.Fatalf("position 0 only ever held %d of the 4 classes: %v - the guaranteed characters are not being shuffled", len(seenAtZero), keys(seenAtZero))
	}
}

func TestImpossibleRequestsAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		options Options
	}{
		{"zero length", Options{Length: 0, UseLower: true}},
		{"negative length", Options{Length: -5, UseLower: true}},
		{"no classes", Options{Length: 10}},
		{"four classes in three characters", Options{Length: 3, UseLower: true, UseUpper: true, UseDigits: true, UseSymbols: true, RequireEach: true}},
		{"exclusion empties a class", Options{Length: 10, UseDigits: true, ExcludeCharSet: Digits}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(tc.options)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrImpossible) {
				t.Fatalf("error should wrap ErrImpossible: %v", err)
			}
		})
	}
}

func TestExcludeRemovesCharacters(t *testing.T) {
	o := DefaultOptions()
	o.Length = 300
	o.ExcludeCharSet = "abc123!@#"
	p, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if i := strings.IndexAny(p, "abc123!@#"); i >= 0 {
		t.Fatalf("%q contains excluded character %q", p, p[i])
	}
}

func TestGeneratedPasswordsDoNotRepeat(t *testing.T) {
	o := DefaultOptions()
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		p, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("generated %q twice in 500 draws - the source is not random", p)
		}
		seen[p] = true
	}
}

// uniform must not have modulo bias. A chi-squared test over an alphabet size that does
// not divide 2^32 evenly is the direct check: `rand % n` would skew the low indices.
func TestUniformHasNoModuloBias(t *testing.T) {
	const (
		n      = 24 // does not divide 2^32
		draws  = 240000
		expect = float64(draws) / float64(n)
	)
	counts := make([]int, n)
	for i := 0; i < draws; i++ {
		v, err := uniform(n)
		if err != nil {
			t.Fatal(err)
		}
		if v >= n {
			t.Fatalf("uniform(%d) returned %d, out of range", n, v)
		}
		counts[v]++
	}

	chi := 0.0
	for _, c := range counts {
		d := float64(c) - expect
		chi += d * d / expect
	}
	// 23 degrees of freedom: the 99.9th percentile is about 49.7. Exceeding that means a
	// real skew rather than sampling noise.
	if chi > 49.7 {
		t.Fatalf("chi-squared %.1f over %d buckets suggests biased selection (counts: %v)", chi, n, counts)
	}
}

func TestUniformRejectsZero(t *testing.T) {
	if _, err := uniform(0); err == nil {
		t.Fatal("uniform(0) should be an error, not a division by zero")
	}
}

func TestPassphraseShape(t *testing.T) {
	p, err := Passphrase(5, "-", false, false)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Split(p, "-")
	if len(words) != 5 {
		t.Fatalf("%q has %d words, want 5", p, len(words))
	}
	for _, w := range words {
		if !inWordlist(w) {
			t.Fatalf("%q is not in the wordlist", w)
		}
	}
}

func TestPassphraseCapitalizeAndDigit(t *testing.T) {
	p, err := Passphrase(3, " ", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if p[len(p)-1] < '0' || p[len(p)-1] > '9' {
		t.Fatalf("%q does not end in a digit", p)
	}
	for _, w := range strings.Fields(strings.TrimRight(p, "0123456789")) {
		if w[0] < 'A' || w[0] > 'Z' {
			t.Fatalf("%q is not capitalised in %q", w, p)
		}
	}
}

func TestPassphraseRejectsZeroWords(t *testing.T) {
	if _, err := Passphrase(0, "-", false, false); !errors.Is(err, ErrImpossible) {
		t.Fatalf("want ErrImpossible, got %v", err)
	}
}

// The entropy figures are reported to users, so they must be arithmetic rather than
// optimism. 256 words is exactly 8 bits each.
func TestPassphraseEntropyMatchesTheWordlist(t *testing.T) {
	if got, want := PassphraseEntropy(6, false), 6*math.Log2(float64(len(Wordlist))); math.Abs(got-want) > 1e-9 {
		t.Fatalf("PassphraseEntropy(6) = %v, want %v", got, want)
	}
	if len(Wordlist) == 256 {
		if got := PassphraseEntropy(6, false); math.Abs(got-48) > 1e-9 {
			t.Fatalf("with a 256-word list, six words should be exactly 48 bits, got %v", got)
		}
	}
	// The appended digit is worth log2(10), not "a lot".
	if got := PassphraseEntropy(6, true) - PassphraseEntropy(6, false); math.Abs(got-math.Log2(10)) > 1e-9 {
		t.Fatalf("the trailing digit is credited with %v bits, want %v", got, math.Log2(10))
	}
}

func TestGeneratedEntropyMatchesTheAlphabet(t *testing.T) {
	o := DefaultOptions()
	o.Length = 20
	alphabet := len(Lower) + len(Upper) + len(Digits) + len(Symbols)
	want := 20 * math.Log2(float64(alphabet))
	if got := GeneratedEntropy(o); math.Abs(got-want) > 1e-9 {
		t.Fatalf("GeneratedEntropy = %v, want %v (alphabet %d)", got, want, alphabet)
	}
}

func TestWordlistIsExactlyEightBitsAndUnique(t *testing.T) {
	if len(Wordlist) != 256 {
		t.Fatalf("wordlist has %d words; the documented 8-bits-per-word figure needs exactly 256", len(Wordlist))
	}
	seen := map[string]bool{}
	for i, w := range Wordlist {
		if seen[w] {
			t.Errorf("duplicate word %q at index %d - duplicates silently reduce entropy", w, i)
		}
		seen[w] = true
		if len(w) < 3 {
			t.Errorf("word %q is too short to be typed reliably", w)
		}
		if strings.ToLower(w) != w {
			t.Errorf("word %q is not lowercase", w)
		}
	}
}

func hasAll(p string) bool {
	return strings.ContainsAny(p, Lower) && strings.ContainsAny(p, Upper) &&
		strings.ContainsAny(p, Digits) && strings.ContainsAny(p, Symbols)
}

func classOf(b byte) string {
	switch {
	case strings.IndexByte(Lower, b) >= 0:
		return "lower"
	case strings.IndexByte(Upper, b) >= 0:
		return "upper"
	case strings.IndexByte(Digits, b) >= 0:
		return "digit"
	default:
		return "symbol"
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func inWordlist(w string) bool {
	for _, x := range Wordlist {
		if x == w {
			return true
		}
	}
	return false
}
