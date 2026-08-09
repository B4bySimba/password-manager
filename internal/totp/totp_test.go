package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 4226 Appendix D: the secret "12345678901234567890" with counters 0-9.
func TestHOTPRFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, expected := range want {
		got, err := HOTP(secret, uint64(counter), 6, SHA1)
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != expected {
			t.Errorf("HOTP(counter=%d) = %s, want %s", counter, got, expected)
		}
	}
}

// RFC 6238 Appendix B, all three algorithms. The seeds differ per algorithm because the
// RFC's reference implementation pads the seed to the hash's block size - a detail that
// trips up every implementation that assumes one shared secret.
func TestTOTPRFC6238Vectors(t *testing.T) {
	seeds := map[Algorithm]string{
		SHA1:   "12345678901234567890",
		SHA256: "12345678901234567890123456789012",
		SHA512: "1234567890123456789012345678901234567890123456789012345678901234",
	}
	cases := []struct {
		unix int64
		sha1 string
		s256 string
		s512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, tc := range cases {
		at := time.Unix(tc.unix, 0).UTC()
		for alg, want := range map[Algorithm]string{SHA1: tc.sha1, SHA256: tc.s256, SHA512: tc.s512} {
			cfg := Config{Secret: []byte(seeds[alg]), Digits: 8, Period: 30, Algorithm: alg}
			got, err := cfg.Generate(at)
			if err != nil {
				t.Fatalf("T=%d %s: %v", tc.unix, alg, err)
			}
			if got != want {
				t.Errorf("TOTP(T=%d, %s) = %s, want %s", tc.unix, alg, got, want)
			}
		}
	}
}

func TestDecodeSecretToleratesRealWorldFormatting(t *testing.T) {
	// All of these are the same secret, formatted the way different services print it.
	canonical := "JBSWY3DPEHPK3PXP"
	want, err := base32.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{
		canonical,
		"jbswy3dpehpk3pxp",
		"JBSW Y3DP EHPK 3PXP",
		"jbsw-y3dp-ehpk-3pxp",
		"  JBSWY3DPEHPK3PXP  ",
		"JBSWY3DPEHPK3PXP====",
	}
	for _, in := range cases {
		got, err := DecodeSecret(in)
		if err != nil {
			t.Fatalf("DecodeSecret(%q): %v", in, err)
		}
		if string(got) != string(want) {
			t.Errorf("DecodeSecret(%q) = %x, want %x", in, got, want)
		}
	}
}

// Unpadded base32 is what almost every service prints, and Go's StdEncoding rejects it.
// Padding it back is the whole reason DecodeSecret exists.
func TestDecodeSecretRepadsUnpaddedInput(t *testing.T) {
	// 26 characters: needs six padding characters to reach a multiple of eight.
	if _, err := DecodeSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY"); err != nil {
		t.Fatalf("unpadded secret rejected: %v", err)
	}
}

func TestDecodeSecretRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "not!valid!base32", "0189"} {
		if _, err := DecodeSecret(in); err == nil {
			t.Errorf("DecodeSecret(%q) accepted invalid input", in)
		}
	}
}

func TestParseURI(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA256"
	cfg, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "Example" {
		t.Errorf("issuer = %q", cfg.Issuer)
	}
	if cfg.Account != "alice@example.com" {
		t.Errorf("account = %q", cfg.Account)
	}
	if cfg.Digits != 8 || cfg.Period != 60 || cfg.Algorithm != SHA256 {
		t.Errorf("parameters = %d digits, %ds, %s", cfg.Digits, cfg.Period, cfg.Algorithm)
	}
}

func TestParseURIDefaults(t *testing.T) {
	cfg, err := ParseURI("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digits != 6 || cfg.Period != 30 || cfg.Algorithm != SHA1 {
		t.Errorf("defaults not applied: %d digits, %ds, %s", cfg.Digits, cfg.Period, cfg.Algorithm)
	}
	if cfg.Account != "alice" || cfg.Issuer != "" {
		t.Errorf("label parsing: issuer=%q account=%q", cfg.Issuer, cfg.Account)
	}
}

func TestParseURIRejections(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		{"https://example.com/?secret=JBSWY3DPEHPK3PXP", "scheme"},
		{"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "only totp"},
		{"otpauth://totp/x", "no secret"},
		{"otpauth://totp/x?secret=!!!", "base32"},
		{"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=many", "digits"},
		{"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "unsupported algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			_, err := ParseURI(tc.uri)
			if err == nil {
				t.Fatalf("accepted %q", tc.uri)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

// The issuer query parameter is authoritative when it disagrees with the label prefix,
// which happens whenever a service renames itself.
func TestParseURIIssuerParameterWins(t *testing.T) {
	cfg, err := ParseURI("otpauth://totp/OldName:alice?secret=JBSWY3DPEHPK3PXP&issuer=NewName")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "NewName" {
		t.Fatalf("issuer = %q, want NewName", cfg.Issuer)
	}
}

func TestVerifyAcceptsWithinTheSkewWindow(t *testing.T) {
	cfg, err := FromSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)

	current, err := cfg.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := cfg.Generate(now.Add(-30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	next, err := cfg.Generate(now.Add(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := cfg.Generate(now.Add(-120 * time.Second))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		code string
		skew int
		want bool
	}{
		{"current code, no skew", current, 0, true},
		{"previous step, no skew", previous, 0, false},
		{"previous step, skew 1", previous, 1, true},
		{"next step, skew 1", next, 1, true},
		{"four steps ago, skew 1", stale, 1, false},
		{"four steps ago, skew 4", stale, 4, true},
		{"wrong code", "000000", 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := cfg.Verify(tc.code, now, tc.skew)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Errorf("Verify(%s, skew=%d) = %v, want %v", tc.code, tc.skew, ok, tc.want)
			}
		})
	}
}

func TestVerifyRejectsNegativeSkew(t *testing.T) {
	cfg, err := FromSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Verify("000000", time.Now(), -1); err == nil {
		t.Fatal("negative skew was accepted")
	}
}

func TestSecondsRemaining(t *testing.T) {
	cfg := Config{Period: 30}
	cases := []struct {
		unix int64
		want int
	}{
		{0, 30},
		{1, 29},
		{29, 1},
		{30, 30},
		{45, 15},
	}
	for _, tc := range cases {
		if got := cfg.SecondsRemaining(time.Unix(tc.unix, 0)); got != tc.want {
			t.Errorf("SecondsRemaining at %d = %d, want %d", tc.unix, got, tc.want)
		}
	}
}

// The code must change exactly at the period boundary and not before, which is what
// makes the countdown display trustworthy.
func TestCodeChangesOnlyAtThePeriodBoundary(t *testing.T) {
	cfg, err := FromSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_040, 0) // exactly on a 30-second boundary

	at0, _ := cfg.Generate(base)
	at29, _ := cfg.Generate(base.Add(29 * time.Second))
	at30, _ := cfg.Generate(base.Add(30 * time.Second))

	if at0 != at29 {
		t.Errorf("the code changed inside a period: %s then %s", at0, at29)
	}
	if at0 == at30 {
		t.Errorf("the code did not change at the boundary: still %s", at0)
	}
}

func TestHOTPRejectsBadDigits(t *testing.T) {
	for _, d := range []int{0, 1, 5, 11, -6} {
		if _, err := HOTP([]byte("secret"), 0, d, SHA1); err == nil {
			t.Errorf("accepted %d digits", d)
		}
	}
}

func TestGenerateRejectsZeroPeriod(t *testing.T) {
	cfg := Config{Secret: []byte("secret"), Digits: 6, Period: 0, Algorithm: SHA1}
	if _, err := cfg.Generate(time.Now()); err == nil {
		t.Fatal("a zero period was accepted; that is a division by zero waiting to happen")
	}
}

func TestFromSecretUsesDefaults(t *testing.T) {
	cfg, err := FromSecret("jbswy3dpehpk3pxp")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digits != 6 || cfg.Period != 30 || cfg.Algorithm != SHA1 {
		t.Fatalf("FromSecret defaults: %+v", cfg)
	}
}
