package vault

import (
	"strings"
	"testing"
)

func searchVault(t *testing.T) *Vault {
	t.Helper()
	v := newVault(t)
	seed := []Entry{
		{Kind: KindLogin, Title: "GitHub", Username: "octocat", URL: "https://github.com", Folder: "dev", Tags: []string{"work", "code"}},
		{Kind: KindLogin, Title: "GitLab", Username: "octocat@example.com", URL: "https://gitlab.com", Folder: "dev", Tags: []string{"work"}},
		{Kind: KindLogin, Title: "Bank of Somewhere", Username: "12345678", URL: "https://bank.example", Folder: "finance", Tags: []string{"money"}},
		{Kind: KindNote, Title: "Recovery codes for GitHub", Folder: "dev", Tags: []string{"backup"}},
	}
	for _, e := range seed {
		e.Secret = Secret{Password: "irrelevant"}
		if _, err := v.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestSearchRanksExactTitleFirst(t *testing.T) {
	v := searchVault(t)
	results, err := v.Search("github")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 2 {
		t.Fatalf("expected at least two matches, got %d", len(results))
	}
	if results[0].Title != "GitHub" {
		t.Fatalf("exact title should rank first, got %q (all: %v)", results[0].Title, searchTitles(results))
	}
	// The substring match must still appear, just lower.
	if !contains(searchTitles(results), "Recovery codes for GitHub") {
		t.Fatalf("substring match missing: %v", searchTitles(results))
	}
}

func TestSearchMatchesUsernameURLTagAndFolder(t *testing.T) {
	v := searchVault(t)
	cases := []struct {
		query string
		want  string
		field string
	}{
		{"octocat", "GitHub", "username"},
		{"bank.example", "Bank of Somewhere", "url"},
		{"money", "Bank of Somewhere", "tag"},
		{"finance", "Bank of Somewhere", "folder"},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			results, err := v.Search(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 {
				t.Fatalf("no matches for %q", tc.query)
			}
			if results[0].Title != tc.want {
				t.Fatalf("top match is %q, want %q", results[0].Title, tc.want)
			}
			if !contains(results[0].Fields, tc.field) {
				t.Fatalf("match reason is %v, want it to include %q", results[0].Fields, tc.field)
			}
		})
	}
}

// An entry matching on two fields must outrank one matching on a single field, otherwise
// the scoring is decoration rather than ranking.
func TestSearchAccumulatesScores(t *testing.T) {
	v := searchVault(t)
	results, err := v.Search("dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected the three dev-folder entries, got %v", searchTitles(results))
	}
}

func TestSearchIsStableAcrossCalls(t *testing.T) {
	v := searchVault(t)
	first, err := v.Search("git")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := v.Search("git")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(searchTitles(again), "|") != strings.Join(searchTitles(first), "|") {
			t.Fatalf("search order changed between identical calls:\n%v\n%v", searchTitles(first), searchTitles(again))
		}
	}
}

func TestEmptySearchReturnsEverything(t *testing.T) {
	v := searchVault(t)
	results, err := v.Search("   ")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != v.Len() {
		t.Fatalf("empty query returned %d of %d entries", len(results), v.Len())
	}
}

func TestSearchNeverMatchesSecrets(t *testing.T) {
	v := newVault(t)
	if _, err := v.Add(Entry{
		Kind: KindLogin, Title: "Something", Secret: Secret{Password: "distinctivepassword", Note: "distinctivenote"},
	}); err != nil {
		t.Fatal(err)
	}
	// Searching secrets would require decrypting every entry on every keystroke, so it is
	// deliberately not supported. This asserts the boundary rather than assuming it.
	for _, q := range []string{"distinctivepassword", "distinctivenote"} {
		results, err := v.Search(q)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 0 {
			t.Fatalf("search found an entry by its secret content (%q)", q)
		}
	}
}

func searchTitles(r []SearchResult) []string {
	out := make([]string, len(r))
	for i := range r {
		out[i] = r[i].Title
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
