// Package cli implements the vault command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"govault/internal/logx"
	"govault/internal/prompt"
	"govault/internal/session"
	"govault/internal/vault"
)

// App carries everything a command needs. Passing it explicitly rather than reaching for
// globals is what makes the commands testable without a terminal.
type App struct {
	Out     io.Writer
	Err     io.Writer
	Log     *logx.Logger
	Config  Config
	Session *session.Store
}

// Config is resolved from environment variables and global flags. Every value has a
// working default, so the tool runs with no configuration at all.
type Config struct {
	VaultPath        string
	SessionTTL       time.Duration
	ClipboardTimeout time.Duration
	Params           vault.KDFParams
	BackupDir        string
	HIBPEnabled      bool
	NoSession        bool
}

// Environment variable names, collected so the .env.example and the README cannot drift
// from the code.
const (
	EnvVaultPath        = "VAULT_PATH"
	EnvSessionTTL       = "VAULT_SESSION_TTL"
	EnvClipboardTimeout = "VAULT_CLIPBOARD_TIMEOUT"
	EnvScryptN          = "VAULT_SCRYPT_N"
	EnvScryptR          = "VAULT_SCRYPT_R"
	EnvScryptP          = "VAULT_SCRYPT_P"
	EnvBackupDir        = "VAULT_BACKUP_DIR"
	EnvHIBP             = "VAULT_HIBP"
	EnvLogLevel         = "VAULT_LOG_LEVEL"
)

// LoadConfig reads the environment. Unparseable values are reported rather than ignored:
// a typo in VAULT_SCRYPT_N that silently reverts to the default would quietly halve the
// protection the user thought they configured.
func LoadConfig() (Config, error) {
	c := Config{
		VaultPath:        defaultVaultPath(),
		SessionTTL:       session.DefaultTTL,
		ClipboardTimeout: 20 * time.Second,
		Params:           vault.DefaultParams(),
		BackupDir:        defaultBackupDir(),
	}
	if v := os.Getenv(EnvVaultPath); v != "" {
		c.VaultPath = v
	}
	if v := os.Getenv(EnvBackupDir); v != "" {
		c.BackupDir = v
	}
	var err error
	if c.SessionTTL, err = durationEnv(EnvSessionTTL, c.SessionTTL); err != nil {
		return c, err
	}
	if c.ClipboardTimeout, err = durationEnv(EnvClipboardTimeout, c.ClipboardTimeout); err != nil {
		return c, err
	}
	if c.Params.N, err = intEnv(EnvScryptN, c.Params.N); err != nil {
		return c, err
	}
	if c.Params.R, err = intEnv(EnvScryptR, c.Params.R); err != nil {
		return c, err
	}
	if c.Params.P, err = intEnv(EnvScryptP, c.Params.P); err != nil {
		return c, err
	}
	switch strings.ToLower(os.Getenv(EnvHIBP)) {
	case "1", "true", "yes", "on":
		c.HIBPEnabled = true
	}
	return c, nil
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration (try 15m, 30s): %w", name, v, err)
	}
	return d, nil
}

func intEnv(name string, def int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number: %w", name, v, err)
	}
	return n, nil
}

func defaultVaultPath() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "vault.gv"
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "govault", "vault.gv")
}

func defaultBackupDir() string { return filepath.Join(filepath.Dir(defaultVaultPath()), "backups") }

// Run dispatches a command. It returns an exit code rather than calling os.Exit, so the
// whole CLI can be driven from a test.
func Run(ctx context.Context, args []string, out, errw io.Writer) int {
	log := logx.New(errw, logx.ParseLevel(os.Getenv(EnvLogLevel)))

	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(errw, "vault: %v\n", err)
		return 2
	}

	global := flag.NewFlagSet("vault", flag.ContinueOnError)
	global.SetOutput(errw)
	global.StringVar(&cfg.VaultPath, "vault", cfg.VaultPath, "path to the vault file")
	global.BoolVar(&cfg.NoSession, "no-session", false, "never read or write an unlock session")
	global.DurationVar(&cfg.SessionTTL, "ttl", cfg.SessionTTL, "unlock session lifetime")
	global.Usage = func() { fmt.Fprint(errw, usage) }

	if err := global.Parse(args); err != nil {
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}

	app := &App{Out: out, Err: errw, Log: log, Config: cfg, Session: session.NewStore()}

	command, cmdArgs := rest[0], rest[1:]
	handler, ok := commands[command]
	if !ok {
		fmt.Fprintf(errw, "vault: unknown command %q\n\n%s", command, usage)
		return 2
	}

	if err := handler(ctx, app, cmdArgs); err != nil {
		return app.reportError(err)
	}
	return 0
}

// reportError turns an error into a message and an exit code. The codes are distinct so
// scripts can branch: 1 is a normal failure, 3 is a wrong password (retry), 4 is
// "locked" (unlock first), 5 is not found.
func (a *App) reportError(err error) int {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, prompt.ErrInterrupted):
		fmt.Fprintln(a.Err, "vault: cancelled")
		return 130 // conventional 128 + SIGINT
	case errors.Is(err, vault.ErrWrongPassword):
		fmt.Fprintln(a.Err, "vault: wrong master password")
		return 3
	case errors.Is(err, vault.ErrLocked), errors.Is(err, session.ErrNoSession):
		fmt.Fprintln(a.Err, "vault: locked; run `vault unlock` first")
		return 4
	case errors.Is(err, vault.ErrNotFound):
		fmt.Fprintf(a.Err, "vault: %v\n", err)
		return 5
	default:
		fmt.Fprintf(a.Err, "vault: %v\n", err)
		return 1
	}
}

type handlerFunc func(ctx context.Context, a *App, args []string) error

var commands map[string]handlerFunc

// init registers commands here rather than in a literal, because several handlers
// reference `commands` (help) and Go rejects the initialisation cycle otherwise.
func init() {
	commands = map[string]handlerFunc{
		"init":          cmdInit,
		"unlock":        cmdUnlock,
		"lock":          cmdLock,
		"status":        cmdStatus,
		"add":           cmdAdd,
		"get":           cmdGet,
		"list":          cmdList,
		"ls":            cmdList,
		"search":        cmdSearch,
		"edit":          cmdEdit,
		"rm":            cmdRemove,
		"generate":      cmdGenerate,
		"gen":           cmdGenerate,
		"strength":      cmdStrength,
		"totp":          cmdTOTP,
		"check":         cmdCheck,
		"import":        cmdImport,
		"export":        cmdExport,
		"backup":        cmdBackup,
		"rotate-master": cmdRotateMaster,
		"help":          cmdHelp,
	}
}

// openVault gets an unlocked vault, preferring a live session over a password prompt.
func (a *App) openVault(_ context.Context) (*vault.Vault, error) {
	if !a.Config.NoSession {
		if sess, err := a.Session.Load(a.Config.VaultPath); err == nil {
			defer sess.Zero()
			v, err := vault.OpenWithKeys(a.Config.VaultPath, sess.Key, sess.MACKey, a.Log)
			if err == nil {
				// Sliding window: using the vault postpones auto-lock.
				if err := a.Session.Refresh(a.Config.VaultPath, a.Config.SessionTTL); err != nil {
					a.Log.Warn("could not refresh session", "err", err)
				}
				return v, nil
			}
			// The session no longer matches this file (rotated password, restored
			// backup). Drop it and fall through to a prompt rather than failing.
			a.Log.Debug("stale session discarded", "err", err)
			_ = a.Session.End(a.Config.VaultPath)
		}
	}

	pw, err := prompt.Password("Master password: ")
	if err != nil {
		return nil, err
	}
	defer zero(pw)
	return vault.Open(a.Config.VaultPath, string(pw), a.Log)
}

// saveVault writes and, if a session is active, keeps it valid. Saving through a session
// leaves the derived keys unchanged, so the stored session stays correct.
func (a *App) saveVault(v *vault.Vault) error { return v.Save() }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const usage = `vault — a zero-knowledge password manager

usage: vault [global flags] <command> [flags] [args]

vault commands
  init                      create a new vault
  unlock                    start an unlock session
  lock                      end the session and forget the keys
  status                    show vault and session state
  rotate-master             change the master password

entry commands
  add                       add an entry (login, note or card)
  get <query>               show an entry; --copy puts the password on the clipboard
  list                      list entries (metadata only, no secrets decrypted)
  search <query>            ranked search over metadata
  edit <query>              change fields on an entry
  rm <query>                delete an entry

tools
  generate                  generate a password or passphrase
  strength <password>       estimate how many guesses a password survives
  totp <query>              print the current TOTP code
  check <query>             check a password against breach corpora (off by default)
  import <file.csv>         import from another manager
  export <file.csv>         export to plaintext CSV (requires --i-understand)
  backup                    copy the encrypted vault to the backup directory

global flags
  --vault PATH              vault file (env VAULT_PATH)
  --ttl DURATION            unlock session lifetime (env VAULT_SESSION_TTL)
  --no-session              never read or write a session

Run "vault help <command>" for a command's flags.
`

func cmdHelp(_ context.Context, a *App, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(a.Out, usage)
		return nil
	}
	name := args[0]
	if _, ok := commands[name]; !ok {
		return fmt.Errorf("unknown command %q", name)
	}
	fs := flagsFor(name)
	if fs == nil {
		fmt.Fprintf(a.Out, "vault %s takes no flags\n", name)
		return nil
	}
	fs.SetOutput(a.Out)
	fmt.Fprintf(a.Out, "vault %s\n\n", name)
	fs.PrintDefaults()
	return nil
}
