# Design notes - Password Manager

## Threat model

Stated first, because every decision below is downstream of it.

**In scope - what this defends against**

| Adversary | Defence |
|---|---|
| Someone who steals the vault file (backup, cloud sync, stolen laptop) | scrypt with memory-hard parameters; AES-256-GCM; no plaintext anywhere in the file, not even titles |
| Someone who *edits* the vault file | The whole header is the AEAD's associated data. Downgrading the version, weakening N, or swapping a sealed secret between entries all fail authentication |
| A shoulder surfer / terminal scrollback | Passwords are masked by default; `--reveal` is explicit; prompts never echo |
| A stale clipboard | Cleared on a timer, and only if the value is still ours |
| A weak master password | Strength estimate at `init`, with a warning that quotes the actual crack time |
| A reused or breached password | Local reuse detection; optional k-anonymity breach lookup |

**Out of scope - what this does *not* defend against**

- **Malware running as your user.** It can read the session file, ptrace the process, log your keystrokes, and read the clipboard. Nothing a userspace password manager does survives this.
- **A compromised kernel or a cold-boot attack.** Keys are zeroed where possible, but Go's garbage collector moves memory and the kernel swaps it. See "What zeroing actually achieves".
- **An attacker who knows your master password.** There is no second factor on the vault itself.
- **Traffic analysis of the breach check.** It is off by default for exactly this reason.
- **Malicious CSV input as a code-execution vector.** Import parses data, but a CSV opened later in a spreadsheet can still carry formula injection; the export is not sanitised for that.

**The weakest link, named explicitly:** the unlock session. It is a file containing live keys, protected by nothing but Unix file permissions. Everything else in this document is stronger than that. It exists because the alternative is re-deriving scrypt on every single command, and users who face that abandon the tool. Sessions are opt-in, short by default, and `--no-session` disables them entirely.

## The file format

```
off  len  field
  0    8  magic "GOVAULT\x1f"
  8    1  format version
  9    1  KDF identifier (1 = scrypt)
 10    4  scrypt N          big-endian uint32
 14    4  scrypt r
 18    4  scrypt p
 22   32  KDF salt
 54   12  key-wrap nonce
 66   48  wrapped vault key (32-byte key + 16-byte GCM tag)
114   12  payload nonce
126   32  header HMAC-SHA256 over bytes [0,126)
158    8  payload length    big-endian uint64
166   ..  payload ciphertext, AAD = header bytes [0,158)
```

Three decisions are load-bearing.

**Fixed offsets, and no allocation sized by an untrusted field.** The header is parsed before any key exists, from a file that may be hostile. `N` is bounds-checked *before* it can be handed to scrypt, because validating it any later would mean allocating gigabytes on an attacker's say-so. The payload length is checked against the actual file size rather than trusted.

**The KDF parameters are stored in the file.** A vault written today still opens after the defaults are raised. The cost is that the parameters are attacker-visible and attacker-editable - which is why they are inside the MAC and the AAD.

**The whole header is the associated data.** Rewriting `N` from 65536 to 2 to make cracking cheap does not produce a weak vault, it produces `wrong master password`. The demo does exactly this and shows the error.

## Key hierarchy

```
master password
      │  scrypt(N, r, p, salt)          ← the expensive step, once per unlock
      ▼
  master key (32 bytes)
      │
      ├─ HKDF-Expand "key-encryption"  ──►  KEK ──► unwraps ──┐
      └─ HKDF-Expand "header-auth"     ──►  MAC key           │
                                                              ▼
                                              vault key (32 random bytes)
                                                              │
                            ┌─────────────────────────────────┴──────────────┐
                            ▼                                                ▼
              per-entry sealed secrets                          the whole payload envelope
              (own nonce, AAD = entry id)                       (own nonce, AAD = header)
```

**Why a random vault key rather than encrypting content with the password-derived key.** Changing the master password rewraps 48 bytes instead of re-encrypting every entry. Rotation is O(1) in the number of credentials - a vault of 5 and a vault of 50,000 take the same time - and the test asserts the sealed blobs are byte-identical afterwards.

**Why HKDF labels.** No two purposes share bytes. If the header-authentication key leaked it must not also decrypt content. The labels are versioned because changing one silently would make every existing vault undecryptable with no useful error.

**Why Expand and not Extract-then-Expand.** The input is already uniformly random scrypt output. Extract exists to condense non-uniform input; running it on a KDF output buys nothing.

**Why per-entry AAD.** Every sealed secret is valid ciphertext under the same vault key, so an AEAD alone would happily accept a blob moved from one entry to another. Binding it to `govault:v1:entry:<id>` makes the ciphertext refuse to move. A test performs exactly that swap and requires it to fail.

## scrypt, by hand

The one primitive not taken from the standard library, because a memory-hard KDF is the whole thing standing between a stolen vault and the master password.

```
scrypt(P, S, N, r, p, dkLen):
    B  = PBKDF2-SHA256(P, S, 1, p·128·r)      spread the password over the buffer
    Bi = ROMix(Bi, N)   for each of p blocks   ← all the cost is here
    DK = PBKDF2-SHA256(P, B, 1, dkLen)         collect the result

ROMix(X, N):
    for i in 0..N-1:  V[i] = X;  X = BlockMix(X)
    for i in 0..N-1:  j = Integerify(X) mod N;  X = BlockMix(X ⊕ V[j])
```

The second loop is the whole trick. `j` depends on the data, so an attacker who declines to store `V` must recompute an average of N/2 BlockMix invocations per lookup. That is the time-memory tradeoff, priced.

`Integerify` reads the final 64-byte block as a little-endian integer mod N. Because N is a power of two this is a mask of one word.

Salsa20/8 is deliberately weak by cipher standards. scrypt needs speed and non-linearity, not collision resistance - the security is in the memory access pattern. A stronger mixing function would make the honest user pay more than the attacker.

**How it is verified:** the three practical RFC 7914 §12 vectors, plus the Salsa20/8 core vector from §8. The core is tested separately on purpose - with only top-level vectors, a bug in `salsa208` and a compensating bug in `blockMix` could hide each other. The 1 GiB fourth vector is skipped; it is a reasonable production setting and an unreasonable unit test.

The two PBKDF2 calls use a single iteration deliberately. They are there to spread and collect, not to add cost.

## Atomic saves

Temp file in the same directory → `chmod 0600` → write → **fsync** → close → `rename`. Rename within a directory is atomic on POSIX, so a crash leaves either the old vault or the new one.

The fsync is not optional. Without it the rename can land before the data does, and a power loss leaves a correctly named, empty vault - which for a password manager means every credential the user owns, gone. A test asserts no temp files survive a successful save.

## What zeroing actually achieves

`crypto.Zero` overwrites a buffer holding key material. Stated honestly:

- **It does** shorten the window in which a key sits in a heap page that could be swapped or captured in a core dump.
- **It does not** erase copies Go's garbage collector made when a slice was reallocated, and it cannot touch copies the kernel made.
- **Go strings cannot be wiped at all.** They are immutable and may be interned. `Entry.Zero` drops the references so the values become collectable immediately; that is the honest ceiling.

Real defence needs `mlock` and a non-moving allocator. This is the 80% that costs nothing, described as the 80% it is.

## Search does not touch secrets

Metadata is stored separately from the sealed secret, so `list` and `search` never decrypt a password. The consequence is that full-text search over notes is not supported: it would mean decrypting every entry on every keystroke, turning a locked-down data set into one fully resident in memory whenever the user types. The tradeoff is in the README rather than hidden, and a test asserts that searching for a stored password verbatim returns nothing.

## The strength estimator

Entropy computed as `length × log2(alphabet)` is correct for a machine-generated password and a lie for anything a person typed. `P@ssw0rd` scores 52 bits under that formula and is cracked instantly.

So the estimator segments the password into recognised patterns - leaked passwords, dictionary words (with leet substitutions reversed), keyboard walks, sequences, repeats, years - prices each by how many candidates an attacker enumerates to reach it, and multiplies. Unmatched runs fall back to brute force over the classes they use.

**Score bands are stricter than zxcvbn's.** zxcvbn's 1e3/1e6/1e8/1e10 thresholds are calibrated for an attacker rate-limited by a login form. The threat here is someone grinding your vault file offline, where 1e10 falls in one second. The bands are 1e6/1e10/1e14/1e18; reaching "strong" needs about 60 bits.

**A bug the tests caught.** The leet reversal was only applied against the dictionary, not against the leaked-password list. `P@ssw0rd` - the canonical example of a password people believe they have disguised - therefore matched nothing and was priced as eight random characters, scoring "strong". Both lists now go through the substitution rules.

**Documented limitation.** Segmentation is greedy longest-match, not a minimum-guess search over all segmentations, and the bundled lists are small (256 words, ~120 leaked passwords). Both cause the estimator to *overrate*, which is the wrong direction to err. `Tr0ub4dor&3` is rated 72 bits here against zxcvbn's ~28, purely because "troubador" is not in the list. A test asserts this so that enlarging the wordlist forces the README claim to be updated with it.

## Unbiased generation

Selection uses rejection sampling, not `rand % len(alphabet)`. Modulo folds 256 byte values unevenly onto an alphabet whose size does not divide 256, making some characters measurably more likely - a real, exploitable narrowing of the search space. A chi-squared test over a 24-character alphabet asserts the distribution is flat.

`RequireEach` places one character per class and then shuffles the whole string with Fisher-Yates. The common shortcut - placing the guaranteed characters at fixed positions - means position 0 is always lowercase, which is information an attacker gets for free. A test draws 400 four-character passwords and requires all four classes to have appeared at position 0.

The passphrase generator reports entropy as `words × log2(len(wordlist))` and *only* that. Capitalisation and a trailing digit are credited at their true worth (0 and 3.3 bits) because the generator's rules are public.

## Breach checking

The k-anonymity range API is what makes this safe to ship: the client sends five hex characters of the password's SHA-1 and receives ~800 suffixes sharing that prefix. Comparison happens locally. The server learns a bucket covering about one 1,048,576th of the hash space.

It is still a network request that only happens because the user has a specific password, so it is **off by default**. Disabled returns `ErrDisabled` rather than "not breached" - confusing "we did not look" with "we looked and it was clean" is how a compromised password survives an audit.

`Add-Padding: true` is sent so an observer watching response sizes cannot narrow down the bucket. Every returned line is scanned even after a match, so the timing does not reveal where in the response the password appeared.

Reuse detection is entirely local: it compares full SHA-1 hashes in-process, so the audit answers the question that matters most without any network at all.

## Terminal echo

Hiding a password means asking the *terminal driver* to stop echoing - the kernel prints your keystrokes before the process ever sees them, so there is no way to do it from inside the program's own I/O. That is three ioctls (`TCGETS`/`TCSETS` on Linux, `TIOCGETA`/`TIOCSETA` on the BSDs), which is why there is no dependency here.

The dangerous part is restoring it: a process that dies between disabling and restoring echo leaves the user with an invisible shell. Hence the deferred restore and `signal.NotifyContext` in `main`.

Reading is one byte at a time. A buffered read would be faster and would also consume past the newline into whatever comes next on the pipe - which for a password prompt means swallowing the user's next command.

On platforms where this is not implemented, the prompt **refuses** rather than reading with echo on. Printing a master password to the screen because a build tag did not match is the kind of silent downgrade this project avoids everywhere else.

## Errors the CLI distinguishes

`Open` verifies the header MAC *before* attempting the payload. Both would fail on a wrong password, but checking the MAC first turns "GCM said no" into the actionable message "wrong master password" - and reserves "corrupt" for the case where the password was right and the bytes were not.

Exit codes follow: 1 general, 2 usage, 3 wrong password, 4 locked, 5 not found, 130 interrupted. Scripts can branch on them.

## What I skipped

- ⬜ **Argon2id.** scrypt is implemented from scratch; Argon2id is the current recommendation and would mean a second hand-written KDF for the same lesson. The format has a KDF identifier byte reserved for it.
- ⬜ **A resident agent** holding keys in `mlock`ed memory, instead of a session file. This is the single biggest available improvement and it is a different program - a daemon with a socket protocol.
- ⬜ **The 7776-word EFF list.** A data-sourcing decision rather than an engineering one. `PassphraseEntropy` computes from `len(Wordlist)`, so swapping it in is one edit and every reported figure follows.
- ⬜ **Full zxcvbn segmentation** (minimum-guess search over all splits) and its 30,000-word dictionary.
- ⬜ **Sync, sharing, and multi-device merge.** A vault with two writers needs conflict resolution, which is a distributed-systems problem wearing a password manager's clothes.
- ⬜ **Hardware token support** (FIDO2 `hmac-secret` as a second factor to the KDF). Genuinely valuable, and needs hardware in CI to test honestly.
- ⬜ **Secure deletion of the underlying blocks.** On a copy-on-write or flash-translated filesystem, overwriting a file does not overwrite the sectors. Only full-disk encryption addresses this.

## What production would add

An audited third-party review - hand-rolled crypto that has not been attacked by anyone but its author should be treated as a learning exercise, which is what this is. Beyond that: Argon2id with parameters calibrated at install time on the actual machine, the agent process, a FIDO2 second factor, encrypted sync with conflict resolution, and a signed release pipeline so the binary a user runs is the code in this repository.
