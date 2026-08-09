package clipboard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClipboard stands in for an external utility, so these tests need no display server.
//
// It is mutex-guarded because CopyWithTimeout does its work on the caller's goroutine
// while the cancellation test observes from another. A real clipboard tool is a separate
// process, so the synchronisation is the fake's problem rather than the package's.
type fakeClipboard struct {
	mu       sync.Mutex
	contents string
	calls    []string
	failOn   string
}

func (f *fakeClipboard) get() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.contents
}

func (f *fakeClipboard) set(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contents = v
}

func (f *fakeClipboard) run(_ context.Context, argv []string, stdin string) (string, error) {
	f.mu.Lock()
	name := argv[0]
	f.calls = append(f.calls, name)
	failOn, contents := f.failOn, f.contents
	f.mu.Unlock()
	if failOn == name {
		return "", errors.New("simulated failure")
	}
	// The first tool in a pair copies, the second pastes; distinguish by whether the
	// command is the one this fake was built for.
	if strings.Contains(name, "copy") || name == "pbcopy" || name == "clip.exe" {
		f.set(stdin)
		return "", nil
	}
	return contents, nil
}

func newFake(paste bool) (*Clipboard, *fakeClipboard) {
	f := &fakeClipboard{}
	t := tool{"wl-copy", []string{"wl-copy"}, []string{"wl-paste", "--no-newline"}}
	if !paste {
		t = tool{"clip.exe", []string{"clip.exe"}, nil}
	}
	return &Clipboard{tool: t, run: f.run}, f
}

func TestCopyAndRead(t *testing.T) {
	cb, fake := newFake(true)
	if err := cb.Copy(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if fake.get() != "hunter2" {
		t.Fatalf("clipboard holds %q", fake.get())
	}
	got, ok := cb.Read(context.Background())
	if !ok || got != "hunter2" {
		t.Fatalf("Read returned %q, %v", got, ok)
	}
}

// The clear must be conditional. Wiping a clipboard the user has since used for
// something else is surprising data loss, and it is avoidable.
func TestClearOnlyWhenTheValueIsStillOurs(t *testing.T) {
	t.Run("still ours", func(t *testing.T) {
		cb, fake := newFake(true)
		if err := cb.Copy(context.Background(), "hunter2"); err != nil {
			t.Fatal(err)
		}
		if err := cb.ClearIfMatches(context.Background(), "hunter2"); err != nil {
			t.Fatal(err)
		}
		if fake.get() != "" {
			t.Fatalf("the clipboard was not cleared: %q", fake.get())
		}
	})

	t.Run("replaced by the user", func(t *testing.T) {
		cb, fake := newFake(true)
		if err := cb.Copy(context.Background(), "hunter2"); err != nil {
			t.Fatal(err)
		}
		fake.set("something the user copied afterwards")

		if err := cb.ClearIfMatches(context.Background(), "hunter2"); err != nil {
			t.Fatal(err)
		}
		if fake.get() != "something the user copied afterwards" {
			t.Fatal("clearing destroyed a value the user had copied since")
		}
	})
}

// A backend that cannot read must clear unconditionally: a password left on the
// clipboard is a worse outcome than an unexpectedly empty clipboard.
func TestClearIsUnconditionalWithoutAPasteCommand(t *testing.T) {
	cb, fake := newFake(false)
	if err := cb.Copy(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	fake.set("something else")

	if err := cb.ClearIfMatches(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if fake.get() != "" {
		t.Fatalf("a read-less backend did not clear: %q", fake.get())
	}
}

func TestTrailingNewlineFromPasteIsIgnored(t *testing.T) {
	cb, fake := newFake(true)
	// Some paste utilities append a newline; that must not count as "the user changed it".
	fake.set("hunter2\n")
	if err := cb.ClearIfMatches(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if fake.get() != "" {
		t.Fatalf("a trailing newline defeated the match: %q", fake.get())
	}
}

func TestCopyWithTimeoutClears(t *testing.T) {
	cb, fake := newFake(true)
	start := time.Now()
	if err := cb.CopyWithTimeout(context.Background(), "hunter2", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("returned after %s, before the timeout elapsed", elapsed)
	}
	if fake.get() != "" {
		t.Fatalf("the clipboard was not cleared after the timeout: %q", fake.get())
	}
}

// Ctrl-C must clear immediately rather than leaving the secret behind — the user is
// abandoning the operation, and the wrong default there is dangerous.
func TestCancellationClearsImmediately(t *testing.T) {
	cb, fake := newFake(true)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- cb.CopyWithTimeout(ctx, "hunter2", time.Hour) }()

	// Wait for the copy to land before cancelling.
	deadline := time.After(2 * time.Second)
	for fake.get() == "" {
		select {
		case <-deadline:
			t.Fatal("the copy never happened")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the wait")
	}
	if fake.get() != "" {
		t.Fatalf("cancelling left the password on the clipboard: %q", fake.get())
	}
}

func TestCopyFailureIsReported(t *testing.T) {
	cb, fake := newFake(true)
	fake.failOn = "wl-copy"
	err := cb.Copy(context.Background(), "hunter2")
	if err == nil {
		t.Fatal("a failing clipboard utility was reported as success")
	}
	if !strings.Contains(err.Error(), "wl-copy") {
		t.Errorf("the error does not name the tool: %v", err)
	}
}

func TestReadFailureIsNotFatal(t *testing.T) {
	cb, fake := newFake(true)
	fake.failOn = "wl-paste"
	if _, ok := cb.Read(context.Background()); ok {
		t.Fatal("Read reported success after the paste command failed")
	}
	// A failed read must fall back to clearing rather than giving up on it.
	if err := cb.ClearIfMatches(context.Background(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if fake.get() != "" {
		t.Fatal("a failed read prevented the clear")
	}
}

func TestDetectErrorNamesTheCandidates(t *testing.T) {
	// Detect only fails when no utility exists; the message must say what was looked for
	// so the user can install one rather than guess.
	if _, err := Detect(); err != nil {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("want ErrUnavailable, got %v", err)
		}
		for _, want := range []string{"wl-copy", "xclip", "pbcopy"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error should mention %q: %v", want, err)
			}
		}
	}
}

func TestNameReportsTheBackend(t *testing.T) {
	cb, _ := newFake(true)
	if cb.Name() != "wl-copy" {
		t.Fatalf("Name = %q", cb.Name())
	}
}
