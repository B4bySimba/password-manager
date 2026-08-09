package vault

import (
	"sort"
	"strings"
)

// SearchResult pairs an entry with why it matched, so the CLI can show the reason and
// the caller can see the ranking is not arbitrary.
type SearchResult struct {
	Metadata
	Score  int
	Fields []string // which fields matched, in match order
}

// Search ranks entries against a query.
//
// Deliberately *not* full text: search only ever touches metadata, never a decrypted
// secret. Searching inside notes would mean decrypting every entry on every keystroke,
// which turns a locked-down data set into one that is fully resident in memory whenever
// the user types. The tradeoff is stated in the README rather than hidden.
//
// Scoring, highest first:
//
//	100  exact title
//	 60  title prefix
//	 40  title substring
//	 30  exact username / tag
//	 20  URL host substring
//	 10  folder or other substring
//
// Multiple matches accumulate, so an entry matching both title and tag outranks one
// matching either alone.
func (v *Vault) Search(query string) ([]SearchResult, error) {
	if v.locked {
		return nil, ErrLocked
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		all, err := v.List()
		if err != nil {
			return nil, err
		}
		out := make([]SearchResult, len(all))
		for i, m := range all {
			out[i] = SearchResult{Metadata: m}
		}
		return out, nil
	}

	var results []SearchResult
	for i := range v.entries {
		m := v.entries[i].metadata()
		score, fields := scoreEntry(m, q)
		if score > 0 {
			results = append(results, SearchResult{Metadata: m, Score: score, Fields: fields})
		}
	}

	// Ties break on title then id, so repeated searches return the same order.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if a, b := strings.ToLower(results[i].Title), strings.ToLower(results[j].Title); a != b {
			return a < b
		}
		return results[i].ID < results[j].ID
	})
	return results, nil
}

func scoreEntry(m Metadata, q string) (int, []string) {
	score := 0
	var fields []string
	add := func(points int, field string) {
		score += points
		fields = append(fields, field)
	}

	title := strings.ToLower(m.Title)
	switch {
	case title == q:
		add(100, "title")
	case strings.HasPrefix(title, q):
		add(60, "title")
	case strings.Contains(title, q):
		add(40, "title")
	}

	if u := strings.ToLower(m.Username); u != "" {
		if u == q {
			add(30, "username")
		} else if strings.Contains(u, q) {
			add(15, "username")
		}
	}
	for _, t := range m.Tags {
		if t == q {
			add(30, "tag")
			break
		}
		if strings.Contains(t, q) {
			add(12, "tag")
			break
		}
	}
	if url := strings.ToLower(m.URL); url != "" && strings.Contains(url, q) {
		add(20, "url")
	}
	if f := strings.ToLower(m.Folder); f != "" && strings.Contains(f, q) {
		add(10, "folder")
	}
	return score, fields
}
