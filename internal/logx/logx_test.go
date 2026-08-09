package logx

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func newTestLogger(level Level) (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := New(&buf, level)
	l.now = func() time.Time { return time.Date(2026, 8, 6, 12, 34, 56, 789_000_000, time.UTC) }
	return l, &buf
}

func TestLevelFiltering(t *testing.T) {
	cases := []struct {
		level Level
		want  []string
		omit  []string
	}{
		{LevelDebug, []string{"d", "i", "w", "e"}, nil},
		{LevelInfo, []string{"i", "w", "e"}, []string{"d"}},
		{LevelWarn, []string{"w", "e"}, []string{"d", "i"}},
		{LevelError, []string{"e"}, []string{"d", "i", "w"}},
		{LevelOff, nil, []string{"d", "i", "w", "e"}},
	}
	for _, tc := range cases {
		t.Run(tc.level.String(), func(t *testing.T) {
			l, buf := newTestLogger(tc.level)
			l.Debug("d")
			l.Info("i")
			l.Warn("w")
			l.Error("e")

			out := buf.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("at level %s, message %q was dropped", tc.level, w)
				}
			}
			for _, o := range tc.omit {
				if strings.Contains(out, " "+o+"\n") {
					t.Errorf("at level %s, message %q should have been filtered", tc.level, o)
				}
			}
		})
	}
}

// LevelOff must silence errors too - a password manager that prints diagnostics into a
// piped stdout consumer breaks scripting, so "off" has to mean off.
func TestLevelOffSilencesEverything(t *testing.T) {
	l, buf := newTestLogger(LevelOff)
	l.Error("this must not appear")
	if buf.Len() != 0 {
		t.Fatalf("LevelOff wrote %q", buf.String())
	}
}

func TestKeyValueFormatting(t *testing.T) {
	l, buf := newTestLogger(LevelDebug)
	l.Info("vault opened", "path", "/tmp/v.gv", "entries", 42)

	out := buf.String()
	for _, want := range []string{"12:34:56.789", "info", "vault opened", "path=/tmp/v.gv", "entries=42"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q is missing %q", out, want)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("the line does not end with a newline")
	}
}

// A dangling key is a bug at the call site. Surfacing it beats dropping the value,
// which is how a log line quietly loses the field that mattered.
func TestOddKeyValueCountIsFlagged(t *testing.T) {
	l, buf := newTestLogger(LevelDebug)
	l.Warn("something", "key", "value", "orphan")
	if !strings.Contains(buf.String(), "!badkey=orphan") {
		t.Fatalf("a dangling key was not flagged: %q", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "DEBUG": LevelDebug, " debug ": LevelDebug,
		"info": LevelInfo, "warn": LevelWarn, "warning": LevelWarn,
		"error": LevelError, "off": LevelOff, "none": LevelOff, "silent": LevelOff,
		// Anything unrecognised, including empty, defaults to warn: a password manager
		// that chats on every invocation trains users to ignore its output.
		"": LevelWarn, "verbose": LevelWarn, "nonsense": LevelWarn,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestOrDiscardHandlesNil(t *testing.T) {
	l := OrDiscard(nil)
	if l == nil {
		t.Fatal("OrDiscard(nil) returned nil")
	}
	l.Error("must not panic")

	existing, _ := newTestLogger(LevelInfo)
	if OrDiscard(existing) != existing {
		t.Fatal("OrDiscard replaced a non-nil logger")
	}
}

func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	l, buf := newTestLogger(LevelDebug)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				l.Info("concurrent", "worker", "x")
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 400 {
		t.Fatalf("got %d lines, want 400", len(lines))
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, "worker=x") {
			t.Fatalf("line %d is torn: %q", i, line)
		}
	}
}
