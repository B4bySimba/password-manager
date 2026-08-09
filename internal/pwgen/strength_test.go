package pwgen

import (
	"strings"
	"testing"
)

// The estimator's job is ordering, not precision. These cases assert the ordering an
// attacker's guess list actually has — which is the thing naive entropy gets wrong.
func TestEstimateScores(t *testing.T) {
	cases := []struct {
		password  string
		wantScore int
		reason    string
	}{
		{"", 0, "empty"},
		{"password", 0, "second entry in every cracking list"},
		{"123456", 0, "the single most common password"},
		{"qwerty", 0, "in the common list"},
		{"P@ssw0rd", 0, "leet substitution on a common word does not help"},
		{"password1", 0, "a digit on the end does not help"},
		{"abcdefgh", 0, "a straight alphabetic sequence"},
		{"qwertyuiop", 0, "a full keyboard row"},
		{"aaaaaaaaaa", 0, "a repeat"},
		{"dragon2019", 0, "common word plus a year"},
		{"kJ8#mZq2", 3, "eight random characters: ~53 bits, about a week of GPU time"},
		{"7Kd!pQ2@vXn", 4, "eleven random characters"},
		{"F3$kR9!wZm2@bQ7#pL4x", 4, "twenty random characters"},
	}

	for _, tc := range cases {
		t.Run(tc.password, func(t *testing.T) {
			got := Estimate(tc.password)
			if got.Score != tc.wantScore {
				t.Errorf("Estimate(%q).Score = %d (%s, %.1f bits), want %d — %s\npatterns: %v",
					tc.password, got.Score, got.Label, got.Entropy, tc.wantScore, tc.reason, got.Patterns)
			}
		})
	}
}

// The single most important property: a password that looks strong by the
// length × log2(alphabet) formula but is a dictionary word must score below a shorter
// random one. If this fails, the estimator is just counting characters.
func TestPatternsBeatNaiveEntropy(t *testing.T) {
	weak := Estimate("Password123!")
	strong := Estimate("kJ8#mZq2")

	if weak.Guesses >= strong.Guesses {
		t.Fatalf("Password123! (%.3g guesses) rated at least as strong as kJ8#mZq2 (%.3g guesses)",
			weak.Guesses, strong.Guesses)
	}
	// Naive entropy would give the 12-character one about 79 bits.
	if weak.Entropy > 40 {
		t.Errorf("Password123! scored %.1f bits; a recognised word plus digits should be far lower", weak.Entropy)
	}
}

// The bundled lists are small, so the estimator overrates anything built from words it
// has never heard of. Asserting the limitation keeps it honest: if the wordlist is ever
// enlarged, this test fails and the README claim gets updated with it.
func TestEstimateOverratesWordsOutsideTheBundledLists(t *testing.T) {
	// zxcvbn, with a 30,000-word dictionary, prices this at roughly 28 bits. Here
	// "troubador" is not in either list, so it is charged as random characters.
	s := Estimate("Tr0ub4dor&3")
	if s.Score < 4 {
		t.Fatalf("Tr0ub4dor&3 now scores %d — if the wordlist grew, update the README's "+
			"stated limitation and this test", s.Score)
	}
	if len(s.Patterns) != 1 || !strings.Contains(s.Patterns[0], "random") {
		t.Fatalf("expected the whole string to fall through to brute force, got %v", s.Patterns)
	}
}

// Leet substitution must be reversed against the leaked-password list, not only against
// the dictionary. "P@ssw0rd" is the canonical case people believe is disguised.
func TestLeetSubstitutionIsReversedAgainstBothLists(t *testing.T) {
	cases := []struct{ password, want string }{
		{"P@ssw0rd", "common-password"},
		{"passw0rd", "common-password"},
		{"dr4gon", "common-password"},
		{"c4ny0n", "word"},
	}
	for _, tc := range cases {
		t.Run(tc.password, func(t *testing.T) {
			s := Estimate(tc.password)
			joined := strings.Join(s.Patterns, " ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("Estimate(%q) saw %v, expected %q", tc.password, s.Patterns, tc.want)
			}
			if s.Score > 0 {
				t.Errorf("Estimate(%q).Score = %d, want 0 — leet on a known word is not protection", tc.password, s.Score)
			}
		})
	}
}

func TestLongerRandomIsAlwaysStronger(t *testing.T) {
	previous := 0.0
	for _, p := range []string{"aB3", "aB3$k", "aB3$kQ9", "aB3$kQ9!mZ", "aB3$kQ9!mZx7&Wp"} {
		g := Estimate(p).Guesses
		if g <= previous {
			t.Fatalf("%q scored %.3g guesses, not more than the shorter password's %.3g", p, g, previous)
		}
		previous = g
	}
}

func TestPatternDetection(t *testing.T) {
	cases := []struct {
		password string
		want     string
	}{
		{"password", "common-password"},
		{"canyon", "word"},
		{"c4ny0n", "leet"},
		{"abcdef", "sequence"},
		{"zxcvbnm", "keyboard-walk"},
		// "asdfghjkl" is in the leaked-password list, so it is priced there instead —
		// a cheaper and more accurate guess than treating it as an adjacency walk.
		{"asdfghjkl", "common-password"},
		{"abababab", "repeat"},
		{"zzzzzz", "repeat"},
		{"1999", "year"},
		{"2026", "year"},
	}
	for _, tc := range cases {
		t.Run(tc.password, func(t *testing.T) {
			s := Estimate(tc.password)
			joined := strings.Join(s.Patterns, " ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("Estimate(%q) recognised %v, expected something containing %q", tc.password, s.Patterns, tc.want)
			}
		})
	}
}

func TestSuggestionsAreActionable(t *testing.T) {
	s := Estimate("password2019")
	if len(s.Suggestions) == 0 {
		t.Fatal("a bad password produced no suggestions")
	}
	joined := strings.ToLower(strings.Join(s.Suggestions, " "))
	if !strings.Contains(joined, "leaked") && !strings.Contains(joined, "dictionary") {
		t.Fatalf("suggestions do not explain the problem: %v", s.Suggestions)
	}
}

// The two crack times differ by exactly the ratio of the attacker speeds. That ratio is
// the argument for scrypt, so it should be visible in the output rather than asserted in
// prose.
func TestCrackTimesReflectTheKDFCost(t *testing.T) {
	s := Estimate("kJ8#mZq2Xp")
	if s.CrackTimeOffline == s.CrackTimeSlowKDF {
		t.Fatalf("both crack times are %q; the slow-hash figure is not being computed", s.CrackTimeOffline)
	}
	if s.CrackTimeOffline == "" || s.CrackTimeSlowKDF == "" {
		t.Fatal("a crack time was left empty")
	}
}

func TestEmptyPasswordIsHandled(t *testing.T) {
	s := Estimate("")
	if s.Score != 0 || s.Guesses != 1 || s.CrackTimeOffline != "instantly" {
		t.Fatalf("Estimate(\"\") = %+v", s)
	}
}

func TestEstimateHandlesUnusualInput(t *testing.T) {
	// Non-ASCII, very long, and single-character inputs must not panic or index out of
	// range — the matchers all slice by byte offset.
	for _, p := range []string{"a", "€", "🔐🔐🔐", strings.Repeat("x", 5000), "\x00\x01\x02", "  "} {
		s := Estimate(p)
		if s.Guesses < 1 {
			t.Errorf("Estimate(%q) produced %v guesses", p, s.Guesses)
		}
	}
}

func BenchmarkEstimate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Estimate("Tr0ub4dor&3correcthorse2019")
	}
}
