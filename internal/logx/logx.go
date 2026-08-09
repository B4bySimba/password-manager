// Package logx is a small structured logger. It exists instead of a dependency, and
// instead of log/slog, for one reason specific to this project: a password manager must
// never log a secret, so the logger is small enough to audit in one sitting.
//
// Everything goes to stderr. Stdout belongs to the user's data — `vault get x --raw`
// piped into another command must not receive a log line.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level orders the four severities.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	// LevelOff silences everything, including errors.
	LevelOff
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "off"
	}
}

// ParseLevel maps a name to a Level, defaulting to warn. A password manager that chats
// on every invocation trains users to ignore its output, including the warnings.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "off", "none", "silent":
		return LevelOff
	default:
		return LevelWarn
	}
}

// Logger writes level-prefixed, key=value lines.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	now   func() time.Time
}

// New returns a logger writing to out.
func New(out io.Writer, level Level) *Logger {
	return &Logger{out: out, level: level, now: time.Now}
}

// FromEnv builds the process logger from VAULT_LOG_LEVEL.
func FromEnv() *Logger { return New(os.Stderr, ParseLevel(os.Getenv("VAULT_LOG_LEVEL"))) }

// Discard drops everything. Used by tests and as the nil-safe default.
func Discard() *Logger { return New(io.Discard, LevelOff) }

// OrDiscard lets every constructor take a *Logger without the caller worrying about nil.
func OrDiscard(l *Logger) *Logger {
	if l == nil {
		return Discard()
	}
	return l
}

func (l *Logger) Debug(msg string, kv ...any) { l.log(LevelDebug, msg, kv...) }
func (l *Logger) Info(msg string, kv ...any)  { l.log(LevelInfo, msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.log(LevelWarn, msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.log(LevelError, msg, kv...) }

func (l *Logger) log(level Level, msg string, kv ...any) {
	if level < l.level || l.level == LevelOff {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-5s %s", l.now().UTC().Format("15:04:05.000"), level, msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, " %v=%v", kv[i], kv[i+1])
	}
	if len(kv)%2 == 1 {
		// A dangling key is a bug at the call site; surface it rather than dropping it.
		fmt.Fprintf(&b, " !badkey=%v", kv[len(kv)-1])
	}
	b.WriteByte('\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.out, b.String())
}
