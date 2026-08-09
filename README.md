# 13 — Password Manager

A zero-knowledge password manager in Go. The vault file is an authenticated binary format
whose *every* field — including entry titles — is inside the encryption envelope. The
master key comes from **scrypt written from scratch** against RFC 7914, content is
AES-256-GCM with per-entry nonces, and rewriting the KDF parameters in the file to make
cracking cheap produces an error rather than a weak vault.

Zero dependencies outside the Go standard library.

## Quick start

```bash
go test ./...          # 164 tests (279 including subtests), -race clean
go run ./examples/demo # the whole system end to end in a temp directory
go build -o vault ./cmd/vault
```

```console
$ vault init
Creating ~/.local/share/govault/vault.gv
There is no recovery for a forgotten master password.
Master password:
Confirm master password:
Vault created: ~/.local/share/govault/vault.gv
  scrypt N=65536 r=8 p=1 — key derivation took 272ms
  Every unlock pays that cost once. So does every guess an attacker makes.

$ vault add --title GitHub --username octocat --generate
Added GitHub (05bc48d94a20)
Generated password: $(jVTo^,w*aK5]akjXr@

$ vault unlock                       # one scrypt derivation, then 15 minutes of use
Unlocked 4 entries in 274ms. Session expires in 15m0s.

$ vault list
05bc48d94a20  login  GitHub                        octocat
cd7053367357  login  Example Bank                  12345678  [totp]
b7cd5578d98c  note   Recovery codes

4 entries. No secret was decrypted to produce this list.

$ vault get github --copy
Copied via wl-copy. Clearing in 20s (Ctrl-C clears now).
Clipboard cleared.
```

## What the demo prints

```
5. TAMPERING IS DETECTED
  weaken scrypt N from 16384 to 2        → vault: wrong master password
  downgrade the format version           → vault: unsupported format version
  flip one bit of the salt               → vault: wrong master password
  flip one bit of the ciphertext         → vault: payload failed authentication

8. STRENGTH ESTIMATION — why entropy formulas lie
  password                 verdict     bits   vs fast hash   vs scrypt
  P@ssw0rd                 terrible     3.0   instantly      instantly
  kJ8#mZq2                 good        52.6   8 days         21 thousand years
  F3$kR9!wZm2@bQ7#pL4x     strong     131.4   centuries      centuries

10. ROTATING THE MASTER PASSWORD IS O(1)
  rotated 4 entries in 87ms
  Only 48 bytes changed: the wrapped vault key. No entry was re-encrypted.
```

`P@ssw0rd` is 52 bits under `length × log2(alphabet)`. It is in every cracking list, so
the estimator reverses the substitutions and prices it at 3.

## Feature checklist

**Cryptography** — ✅ **scrypt from scratch** (Salsa20/8 → BlockMix → ROMix), verified
against the RFC 7914 §12 vectors and the §8 core vector · ✅ AES-256-GCM · ✅ per-entry
random nonces · ✅ HKDF subkeys with versioned domain-separation labels · ✅ HMAC-SHA256
over the header · ✅ constant-time comparison · ✅ bounds-checked KDF parameters

**Vault format** — ✅ versioned binary format, byte layout documented in
[docs/design.md](docs/design.md) · ✅ random vault key wrapped by the password-derived key,
so rotation is **O(1)** · ✅ whole header as AEAD associated data · ✅ per-entry AAD binding
a sealed secret to its id · ✅ atomic saves (temp + fsync + rename) · ✅ 0600 throughout ·
✅ hostile-input parsing with no allocation sized by an untrusted field

**Entries** — ✅ logins, notes, cards · ✅ folders and tags · ✅ TOTP secrets ·
✅ metadata/secret split so `list` and `search` decrypt nothing · ✅ ranked search with
match reasons · ✅ id, id-prefix and title resolution, with ambiguity refused

**CLI** — ✅ `init` `unlock` `lock` `status` `add` `get` `list` `search` `edit` `rm`
`generate` `strength` `totp` `check` `import` `export` `backup` `rotate-master` `help` ·
✅ no-echo password prompts via termios · ✅ auto-lock with a sliding window ·
✅ clipboard copy with conditional clear · ✅ SIGINT/SIGTERM cancel cleanly ·
✅ distinguishable exit codes · ✅ config from env with a `.env.example`

**Tools** — ✅ unbiased generator (rejection sampling, chi-squared tested) ·
✅ passphrases with honest entropy arithmetic · ✅ pattern-based strength estimator ·
✅ RFC 4226/6238 TOTP with `otpauth://` parsing · ✅ HIBP k-anonymity, off by default,
mocked in tests · ✅ CSV import mapping Bitwarden/Chrome/1Password/LastPass headers ·
✅ CSV export gated behind `--i-understand` · ✅ encrypted backup that needs no password

- ⬜ **Argon2id** — the current recommendation; a second hand-written KDF for the same
  lesson. The format reserves a KDF identifier byte for it.
- ⬜ **A resident agent** holding keys in `mlock`ed memory instead of a session file. The
  single biggest available improvement, and a different program.
- ⬜ **The 7776-word EFF list** — a data decision, not an engineering one. Entropy is
  computed from `len(Wordlist)`, so swapping it in updates every reported figure.
- ⬜ **Full zxcvbn segmentation** (minimum-guess search) and its 30k dictionary.
- ⬜ **Sync and multi-device merge** — a distributed-systems problem in disguise.
- ⬜ **FIDO2 `hmac-secret`** as a second KDF factor — needs hardware to test honestly.

## API reference

```go
// Vault lifecycle
vault.Create(path, password string, params KDFParams, log *logx.Logger) (*Vault, error)
vault.Open(path, password string, log *logx.Logger) (*Vault, error)
vault.OpenWithKeys(path string, vaultKey, macKey []byte, log *logx.Logger) (*Vault, error)
(*Vault) Save() error
(*Vault) RotateMaster(newPassword string, params KDFParams) error   // O(1) in entries
(*Vault) Lock() / Close()          // zeroes the keys; later calls return ErrLocked
(*Vault) SessionKeys() (vaultKey, macKey []byte, err error)

// Entries
(*Vault) Add(Entry) (id string, err error)   Get(id) (Entry, error)
(*Vault) Update(Entry) error                 Delete(id) error
(*Vault) List() ([]Metadata, error)          Search(query) ([]SearchResult, error)
(*Vault) Resolve(query) (id string, err error)   // id, id prefix, or exact title

// Primitives
crypto.Scrypt(password, salt []byte, n, r, p, keyLen int) ([]byte, error)
crypto.Seal / Open / SealWithNonce / OpenWithNonce / Subkey / MAC / VerifyMAC / Zero

// Tools
pwgen.Generate(Options) (string, error)      pwgen.Passphrase(words, sep, cap, digit)
pwgen.Estimate(password) Strength            pwgen.GeneratedEntropy(Options) float64
totp.HOTP / Config.Generate / Verify / ParseURI / FromSecret / DecodeSecret
hibp.New(enabled).Check(ctx, password) (Result, error)   hibp.HashPrefix(password)
portable.Import / Export / Backup
session.Store: Start / Load / Refresh / End / Remaining
```

Errors callers branch on: `vault.ErrWrongPassword`, `ErrCorrupt`, `ErrNotAVault`,
`ErrUnsupportedVer`, `ErrNotFound`, `ErrLocked`; `crypto.ErrAuthentication`,
`ErrScryptParams`; `hibp.ErrDisabled`; `pwgen.ErrImpossible`; `session.ErrNoSession`.

## How it works

```
master password
      │  scrypt(N=65536, r=8, p=1, salt)     ← ~270ms, 64 MiB of scratch memory
      ▼
  master key
      ├─ HKDF "key-encryption"  ──► KEK ────► unwraps ──┐
      └─ HKDF "header-auth"     ──► MAC key             │
                                                        ▼
                                        vault key (32 random bytes)
                                                        │
                        ┌───────────────────────────────┴──────────────┐
                        ▼                                              ▼
          per-entry sealed secrets                     the whole payload envelope
          (own nonce, AAD = entry id)                  (own nonce, AAD = header)


file:  [ magic | ver | kdf | N r p | salt | wrapNonce | wrappedKey |
         payloadNonce | headerMAC | payloadLen ]  ← all of this is the AAD
       [ ciphertext ]
```

Content is encrypted under a **random** vault key that the password merely wraps. That is
why changing the master password rewraps 48 bytes instead of re-encrypting every entry,
and why a test can assert the sealed blobs are byte-identical after rotation.

## Design decisions & tradeoffs

- **scrypt by hand, everything else from the standard library.** The memory-hard KDF is
  the thing worth understanding; AES-GCM and HMAC are not improved by reimplementation.
  Go 1.24+ has `crypto/pbkdf2` and `crypto/hkdf` in the standard library, so this stays at
  zero dependencies.
- **The header is the associated data.** Parameter downgrade becomes an authentication
  failure instead of a cheaper cracking job.
- **Per-entry AAD.** Every sealed secret is valid ciphertext under the same key, so
  without it an attacker with write access could move the bank blob onto a forum entry.
- **Metadata is separate from secrets**, so `list` and `search` never decrypt a password.
  The cost is no full-text search over notes — that would mean decrypting everything on
  every keystroke.
- **Weak master passwords warn, they do not block.** A hard check teaches users to append
  `1!` until it passes, which yields a predictable password rather than a strong one.
- **Score bands are stricter than zxcvbn's** (1e6/1e10/1e14/1e18 rather than
  1e3/1e6/1e8/1e10) because the threat is an offline attack on a stolen file, not a
  rate-limited login form.
- **The session file is the weakest link and is documented as such** — see the threat
  model. Opt-in, short-lived, `--no-session` to disable.

## Benchmarks

`go test -bench . ./internal/crypto ./internal/pwgen`, and figures the demo prints:

| Measurement | Result |
|---|---|
| scrypt N=4096 r=8 p=1 | 18ms, 4 MiB scratch — 214 days per billion guesses |
| scrypt N=16384 r=8 p=1 | 71ms, 16 MiB — 2 years per billion guesses |
| scrypt **N=65536 r=8 p=1** (default) | 272ms, 64 MiB — **9 years per billion guesses** |
| Master-password rotation, 4 entries | 87ms — and the same for 50,000 |
| Generator uniformity, 240k draws over 24 symbols | χ² = 18.4 (99.9th percentile is 49.7) |
| Vault size, 4 entries | 1492 bytes = 166 header + 1326 payload |

The memory column is the argument: an attacker's GPU has thousands of cores and nothing
like thousands of times the memory bandwidth.

## Known limitations

**This is a learning exercise, not audited software.** Hand-rolled cryptography that
nobody but its author has attacked should be treated as exactly that. Use a reviewed
password manager for real credentials.

Beyond that: the session file is protected only by Unix permissions; Go strings holding
secrets cannot be wiped, only released; overwriting a file does not overwrite sectors on
copy-on-write or flash-translated storage; the strength estimator overrates anything built
from words outside its 256-entry list; and the clipboard is readable by any process on the
desktop for as long as the value is there. The full threat model — including what is
explicitly *out* of scope — is the first section of [docs/design.md](docs/design.md).

## Dependency justification

**Zero dependencies.** `go.mod` has no `require` block.

From the standard library: `crypto/aes`, `crypto/cipher` (AES-256-GCM), `crypto/hmac`,
`crypto/sha1`, `crypto/sha256`, `crypto/sha512`, `crypto/rand`, `crypto/subtle`,
`crypto/pbkdf2` and `crypto/hkdf` (both stdlib since Go 1.24), `encoding/base32`,
`encoding/csv`, `syscall` for termios.

Written by hand rather than imported: **scrypt** (`golang.org/x/crypto/scrypt` — this is
the thing the project exists to teach), the vault format, TOTP
(`github.com/pquerna/otp`), the password generator and strength estimator
(`github.com/nbutton23/zxcvbn-go`), the HIBP client, CSV column mapping, the CLI
(`spf13/cobra`), the logger, and no-echo terminal input (`golang.org/x/term`).
