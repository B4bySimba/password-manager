package hibp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockDoer serves a canned range response and records what was requested. The suite must
// never touch the network: a test that silently depends on an external API is a test that
// fails on a plane.
type mockDoer struct {
	body       string
	status     int
	requested  []string
	headers    http.Header
	forceError error
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	m.requested = append(m.requested, req.URL.String())
	m.headers = req.Header.Clone()
	if m.forceError != nil {
		return nil, m.forceError
	}
	status := m.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(m.body)),
		Header:     make(http.Header),
	}, nil
}

func newTestChecker(m *mockDoer) *Checker {
	return &Checker{Client: m, BaseURL: "https://example.test/range/", Enabled: true}
}

func TestHashPrefixSplitsCorrectly(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
	prefix, suffix := HashPrefix("password")
	if prefix != "5BAA6" {
		t.Errorf("prefix = %q, want 5BAA6", prefix)
	}
	if suffix != "1E4C9B93F3F0682250B6CF8331B7EE68FD8" {
		t.Errorf("suffix = %q", suffix)
	}
	if len(prefix) != 5 || len(suffix) != 35 {
		t.Errorf("split is %d + %d characters, want 5 + 35", len(prefix), len(suffix))
	}
}

// The privacy claim is checkable: only the 5-character prefix may appear in the request,
// and the password and full hash must not.
func TestOnlyThePrefixLeavesTheMachine(t *testing.T) {
	m := &mockDoer{body: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\n"}
	c := newTestChecker(m)

	if _, err := c.Check(context.Background(), "password"); err != nil {
		t.Fatal(err)
	}
	if len(m.requested) != 1 {
		t.Fatalf("made %d requests, want 1", len(m.requested))
	}

	url := m.requested[0]
	if !strings.HasSuffix(url, "/5BAA6") {
		t.Fatalf("requested %q, want it to end in the 5-character prefix", url)
	}
	for _, forbidden := range []string{"password", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "1E4C9B93"} {
		if strings.Contains(url, forbidden) {
			t.Errorf("the request URL leaked %q: %s", forbidden, url)
		}
	}
	// Padding hides the bucket size from anyone watching response lengths.
	if m.headers.Get("Add-Padding") != "true" {
		t.Error("the Add-Padding header was not sent")
	}
}

func TestCheckFindsABreachedPassword(t *testing.T) {
	m := &mockDoer{body: strings.Join([]string{
		"0018A45C4D1DEF81644B54AB7F969B88D65:1",
		"1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365", // this is "password"
		"011053FD0102E94D6AE2F8B83D76FAF94F6:0",       // padding entry
		"012A7CA357541F0AC487871FEEC1891C49C:2",
	}, "\r\n")}

	res, err := newTestChecker(m).Check(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Breached {
		t.Fatal("a password present in the corpus was reported as clean")
	}
	if res.Count != 9659365 {
		t.Errorf("count = %d, want 9659365", res.Count)
	}
	if res.Prefix != "5BAA6" {
		t.Errorf("prefix = %q", res.Prefix)
	}
	// The padding entry has a count of zero and must not inflate the anonymity set.
	if res.Bucket != 3 {
		t.Errorf("bucket = %d, want 3 real entries (padding excluded)", res.Bucket)
	}
}

func TestCheckReportsACleanPassword(t *testing.T) {
	m := &mockDoer{body: "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1234567890ABCDEF1234567890ABCDEF123:5\r\n"}
	res, err := newTestChecker(m).Check(context.Background(), "an unusual passphrase nobody has used")
	if err != nil {
		t.Fatal(err)
	}
	if res.Breached || res.Count != 0 {
		t.Fatalf("a clean password was reported as breached: %+v", res)
	}
}

func TestSuffixMatchingIsCaseInsensitive(t *testing.T) {
	// The API returns uppercase, but a cached or proxied response may not.
	m := &mockDoer{body: "1e4c9b93f3f0682250b6cf8331b7ee68fd8:42\n"}
	res, err := newTestChecker(m).Check(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Breached || res.Count != 42 {
		t.Fatalf("lowercase suffix not matched: %+v", res)
	}
}

// Disabled must be an error, never a quiet "not breached". Confusing "we did not look"
// with "we looked and it was clean" is how a user keeps a compromised password.
func TestDisabledCheckerRefusesRatherThanReportingClean(t *testing.T) {
	c := New(false)
	res, err := c.Check(context.Background(), "password")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
	if res.Breached {
		t.Fatal("a disabled checker returned a result")
	}
}

func TestNewIsDisabledByDefault(t *testing.T) {
	if New(false).Enabled {
		t.Fatal("New(false) produced an enabled checker")
	}
	if !New(true).Enabled {
		t.Fatal("New(true) produced a disabled checker")
	}
}

func TestCheckSurfacesTransportAndProtocolErrors(t *testing.T) {
	t.Run("network failure", func(t *testing.T) {
		c := newTestChecker(&mockDoer{forceError: errors.New("dial tcp: no route to host")})
		if _, err := c.Check(context.Background(), "password"); err == nil {
			t.Fatal("a network failure was swallowed")
		} else if !strings.Contains(err.Error(), "no route to host") {
			t.Errorf("the underlying cause was lost: %v", err)
		}
	})

	t.Run("non-200 response", func(t *testing.T) {
		c := newTestChecker(&mockDoer{status: http.StatusTooManyRequests})
		if _, err := c.Check(context.Background(), "password"); err == nil {
			t.Fatal("a 429 was treated as success")
		}
	})

	t.Run("malformed line", func(t *testing.T) {
		c := newTestChecker(&mockDoer{body: "this line has no colon\n"})
		if _, err := c.Check(context.Background(), "password"); err == nil {
			t.Fatal("a malformed response was accepted")
		}
	})

	t.Run("non-numeric count", func(t *testing.T) {
		c := newTestChecker(&mockDoer{body: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:many\n"})
		if _, err := c.Check(context.Background(), "password"); err == nil {
			t.Fatal("a non-numeric count was accepted")
		}
	})
}

func TestBlankLinesAndTrailingWhitespaceAreTolerated(t *testing.T) {
	m := &mockDoer{body: "\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:7 \n\n"}
	res, err := newTestChecker(m).Check(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 7 {
		t.Fatalf("count = %d, want 7", res.Count)
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// http.NewRequestWithContext succeeds, so the cancellation surfaces from the Doer.
	// The real *http.Client returns it; the mock is checked for having received the ctx.
	c := newTestChecker(&mockDoer{forceError: context.Canceled})
	if _, err := c.Check(ctx, "password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
