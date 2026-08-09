package pwgen

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Strength is the result of estimating a human-chosen password.
type Strength struct {
	Guesses     float64  // estimated guesses an attacker needs, on average
	Entropy     float64  // log2(Guesses) - comparable with GeneratedEntropy
	Score       int      // 0 (terrible) to 4 (strong)
	Label       string   // human-readable score
	Patterns    []string // what the estimator recognised, in order
	Suggestions []string
	// CrackTime is how long the guesses take at two very different attacker speeds.
	CrackTimeOffline string // 10^10 guesses/s: leaked hashes, GPU cluster, fast hash
	CrackTimeSlowKDF string // 10^4 guesses/s: leaked hashes protected by scrypt
}

// Attacker speeds. The gap between them is the entire argument for a memory-hard KDF:
// the same password is worth a million times more when the hash is expensive.
const (
	guessesPerSecFast = 1e10
	guessesPerSecSlow = 1e4
)

// Estimate scores a human-chosen password.
//
// The idea, borrowed from zxcvbn: entropy computed as length × log2(alphabet) is a lie
// for anything a person typed. "Password1!" scores 65 bits under that formula and is
// cracked instantly. What matters is how many guesses an *informed* attacker needs, and
// an informed attacker guesses words, dates, keyboard walks, and leet substitutions
// before they guess random strings.
//
// So this segments the password into recognised patterns, prices each pattern by how
// many candidates an attacker would enumerate to reach it, and multiplies. Unmatched
// runs fall back to brute force over the classes they use.
//
// Simplification versus real zxcvbn, stated plainly: segmentation here is greedy
// longest-match left to right, not a minimum-guess search over all segmentations. Greedy
// can overprice a password whose optimal split differs - it errs toward "stronger",
// which is the wrong direction to err, so the README marks full search as not done.
func Estimate(password string) Strength {
	if password == "" {
		return Strength{
			Guesses: 1, Entropy: 0, Score: 0, Label: "empty",
			Suggestions:      []string{"Use a password."},
			CrackTimeOffline: "instantly", CrackTimeSlowKDF: "instantly",
		}
	}

	segments := segment(password)

	guesses := 1.0
	var patterns []string
	for _, s := range segments {
		guesses *= s.guesses
		patterns = append(patterns, s.describe())
	}
	// An attacker also has to try the *arrangement* of patterns. Charging a factor per
	// extra segment is crude but directionally right: "correcthorse" is easier than
	// "horse7correct$battery" even at equal length.
	if n := len(segments); n > 1 {
		guesses *= math.Pow(2, float64(n-1))
	}
	if guesses < 1 {
		guesses = 1
	}

	s := Strength{
		Guesses:  guesses,
		Entropy:  math.Log2(guesses),
		Patterns: patterns,
	}
	s.Score, s.Label = score(guesses)
	s.CrackTimeOffline = humanDuration(guesses / guessesPerSecFast)
	s.CrackTimeSlowKDF = humanDuration(guesses / guessesPerSecSlow)
	s.Suggestions = suggestions(password, segments, s.Score)
	return s
}

// --- segmentation ----------------------------------------------------------------------

type kind int

const (
	kindBrute kind = iota
	kindWord
	kindCommon
	kindSequence
	kindKeyboard
	kindRepeat
	kindYear
)

type match struct {
	kind    kind
	text    string
	guesses float64
	note    string
}

func (m match) describe() string {
	name := map[kind]string{
		kindBrute: "random", kindWord: "word", kindCommon: "common-password",
		kindSequence: "sequence", kindKeyboard: "keyboard-walk", kindRepeat: "repeat",
		kindYear: "year",
	}[m.kind]
	if m.note != "" {
		return fmt.Sprintf("%q %s (%s)", m.text, name, m.note)
	}
	return fmt.Sprintf("%q %s", m.text, name)
}

func segment(password string) []match {
	lower := strings.ToLower(password)
	var out []match
	i := 0
	var bruteRun strings.Builder

	flush := func() {
		if bruteRun.Len() > 0 {
			out = append(out, bruteMatch(bruteRun.String()))
			bruteRun.Reset()
		}
	}

	for i < len(password) {
		if m, n := matchAt(password, lower, i); n > 0 {
			flush()
			out = append(out, m)
			i += n
			continue
		}
		bruteRun.WriteByte(password[i])
		i++
	}
	flush()
	return out
}

// matchAt tries every pattern at position i and returns the longest match.
func matchAt(password, lower string, i int) (match, int) {
	var best match
	bestLen := 0
	consider := func(m match, n int) {
		if n > bestLen {
			best, bestLen = m, n
		}
	}

	if m, n := matchCommon(lower, i); n > 0 {
		consider(m, n)
	}
	if m, n := matchWord(lower, i); n > 0 {
		consider(m, n)
	}
	if m, n := matchYear(password, i); n > 0 {
		consider(m, n)
	}
	if m, n := matchRepeat(password, i); n > 0 {
		consider(m, n)
	}
	if m, n := matchSequence(lower, i); n > 0 {
		consider(m, n)
	}
	if m, n := matchKeyboard(lower, i); n > 0 {
		consider(m, n)
	}
	return best, bestLen
}

// unleet reverses the substitutions people believe make a word unguessable. They do not:
// an attacker's wordlist is expanded with these rules before the first guess is sent.
var leet = strings.NewReplacer(
	"4", "a", "@", "a", "8", "b", "(", "c", "3", "e", "6", "g",
	"1", "l", "!", "i", "0", "o", "5", "s", "$", "s", "7", "t", "+", "t",
)

func matchWord(lower string, i int) (match, int) {
	// Longest word first so "planet" beats "plan".
	for n := min(12, len(lower)-i); n >= 3; n-- {
		candidate := lower[i : i+n]
		plain := candidate
		leetUsed := false
		if idx := wordIndex(candidate); idx < 0 {
			plain = leet.Replace(candidate)
			leetUsed = plain != candidate
		}
		idx := wordIndex(plain)
		if idx < 0 {
			continue
		}
		// Guesses = the attacker's rank of that word in a frequency-ordered list.
		g := float64(idx + 1)
		note := ""
		if leetUsed {
			// Leet substitution multiplies the candidate list a little, not a lot.
			g *= 4
			note = "leet substitution adds almost nothing"
		}
		return match{kind: kindWord, text: lower[i : i+n], guesses: g, note: note}, n
	}
	return match{}, 0
}

func matchCommon(lower string, i int) (match, int) {
	for n := min(16, len(lower)-i); n >= 4; n-- {
		candidate := lower[i : i+n]

		idx := commonIndex(candidate)
		leetUsed := false
		if idx < 0 {
			// The leaked-password list must be consulted through the leet rules too, not
			// just the dictionary. Without this, "P@ssw0rd" - which is the canonical
			// example of a password people believe they have disguised - matches nothing
			// and gets priced as eight random characters.
			if plain := leet.Replace(candidate); plain != candidate {
				idx = commonIndex(plain)
				leetUsed = idx >= 0
			}
		}
		if idx < 0 {
			continue
		}

		g := float64(idx + 1)
		note := fmt.Sprintf("rank %d in a leaked-password list", idx+1)
		if leetUsed {
			g *= 4
			note += ", leet substitution reverses trivially"
		}
		return match{kind: kindCommon, text: candidate, guesses: g, note: note}, n
	}
	return match{}, 0
}

// matchYear catches 1900-2099, which is what dates in passwords almost always are.
func matchYear(password string, i int) (match, int) {
	if i+4 > len(password) {
		return match{}, 0
	}
	s := password[i : i+4]
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return match{}, 0
		}
	}
	y := (int(s[0]-'0'))*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
	if y < 1900 || y > 2099 {
		return match{}, 0
	}
	return match{kind: kindYear, text: s, guesses: 200, note: "years are guessed early"}, 4
}

// matchRepeat catches "aaaa" and "abcabcabc".
func matchRepeat(password string, i int) (match, int) {
	for unit := 1; unit <= 4 && i+unit*2 <= len(password); unit++ {
		base := password[i : i+unit]
		reps := 1
		for i+unit*(reps+1) <= len(password) && password[i+unit*reps:i+unit*(reps+1)] == base {
			reps++
		}
		if reps >= 3 || (unit >= 2 && reps >= 2) {
			n := unit * reps
			// Cost is guessing the unit plus the repeat count, not the whole string.
			return match{
				kind: kindRepeat, text: password[i : i+n],
				guesses: math.Pow(26, float64(unit)) * float64(reps),
				note:    fmt.Sprintf("%q × %d", base, reps),
			}, n
		}
	}
	return match{}, 0
}

// matchSequence catches runs like "abcdef", "98765", "zyx".
func matchSequence(lower string, i int) (match, int) {
	if i+3 > len(lower) {
		return match{}, 0
	}
	for _, dir := range []int{1, -1} {
		n := 1
		for i+n < len(lower) && int(lower[i+n])-int(lower[i+n-1]) == dir {
			n++
		}
		if n >= 3 && (isAlphaNum(lower[i])) {
			return match{kind: kindSequence, text: lower[i : i+n], guesses: float64(n) * 30}, n
		}
	}
	return match{}, 0
}

// Keyboard rows, used to catch adjacency walks in either direction.
var keyboardRows = []string{"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"}

func matchKeyboard(lower string, i int) (match, int) {
	for _, row := range keyboardRows {
		for _, dir := range []int{1, -1} {
			n := 0
			pos := strings.IndexByte(row, lower[i])
			if pos < 0 {
				continue
			}
			for i+n < len(lower) {
				p := strings.IndexByte(row, lower[i+n])
				if p != pos+dir*n {
					break
				}
				n++
			}
			if n >= 4 {
				return match{kind: kindKeyboard, text: lower[i : i+n], guesses: float64(n) * 50}, n
			}
		}
	}
	return match{}, 0
}

// bruteMatch prices an unrecognised run at the size of the alphabet it actually uses.
func bruteMatch(s string) match {
	var lower, upper, digit, symbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	size := 0
	for _, use := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {symbol, 33}} {
		if use.on {
			size += use.n
		}
	}
	if size == 0 {
		size = 26
	}
	return match{kind: kindBrute, text: s, guesses: math.Pow(float64(size), float64(len(s)))}
}

// --- scoring and presentation -------------------------------------------------------

// score maps guesses onto a 0-4 band.
//
// The thresholds are deliberately stricter than zxcvbn's (1e3/1e6/1e8/1e10), which are
// calibrated for an attacker rate-limited by a login form. The threat here is different:
// someone has your *vault file* and is grinding it offline. At 10^10 guesses per second
// against a fast hash, zxcvbn's "strong" 1e10 falls in one second.
//
// So the bands are set against offline attack: 1e6, 1e10, 1e14, 1e18. Reaching 4 needs
// roughly 60 bits, which is about eleven random printable characters. A user who has been
// told "strong" should not be reachable in a weekend.
func score(guesses float64) (int, string) {
	switch l := math.Log10(guesses); {
	case l < 6:
		return 0, "terrible"
	case l < 10:
		return 1, "weak"
	case l < 14:
		return 2, "fair"
	case l < 18:
		return 3, "good"
	default:
		return 4, "strong"
	}
}

func humanDuration(seconds float64) string {
	switch {
	case seconds < 1:
		return "instantly"
	case seconds < 60:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.0f hours", seconds/3600)
	case seconds < 86400*365:
		return fmt.Sprintf("%.0f days", seconds/86400)
	case seconds < 86400*365*1000:
		return fmt.Sprintf("%.0f years", seconds/(86400*365))
	case seconds < 86400*365*1e9:
		return fmt.Sprintf("%.0f thousand years", seconds/(86400*365*1000))
	default:
		return "centuries"
	}
}

func suggestions(password string, segments []match, sc int) []string {
	var out []string
	for _, s := range segments {
		switch s.kind {
		case kindCommon:
			out = append(out, fmt.Sprintf("%q appears in leaked-password lists; it is tried in the first seconds.", s.text))
		case kindWord:
			out = append(out, fmt.Sprintf("%q is a dictionary word. Substituting digits for letters does not hide it.", s.text))
		case kindSequence:
			out = append(out, fmt.Sprintf("%q is a straight sequence.", s.text))
		case kindKeyboard:
			out = append(out, fmt.Sprintf("%q is a walk across the keyboard.", s.text))
		case kindRepeat:
			out = append(out, fmt.Sprintf("%q is a repeat.", s.text))
		case kindYear:
			out = append(out, fmt.Sprintf("%q looks like a year.", s.text))
		}
		if len(out) >= 3 {
			break
		}
	}
	if len(password) < 12 {
		out = append(out, "Length beats complexity: every extra character multiplies the search space.")
	}
	if sc >= 4 && len(out) == 0 {
		out = append(out, "No recognised patterns.")
	}
	return out
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func wordIndex(w string) int {
	for i, x := range Wordlist {
		if x == w {
			return i
		}
	}
	return -1
}

func commonIndex(w string) int {
	for i, x := range CommonPasswords {
		if x == w {
			return i
		}
	}
	return -1
}
