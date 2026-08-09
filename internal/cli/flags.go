package cli

import "flag"

// Each command's flags live in a struct with a bind method, so `vault help <cmd>` can
// construct an empty flag set and print the defaults without duplicating the definitions.

type addFlags struct {
	kind      string
	title     string
	username  string
	url       string
	folder    string
	tags      string
	note      string
	totp      string
	generate  bool
	length    int
	password  string
	cardNum   string
	cardHold  string
	cardExp   string
	cardCVV   string
	cardPIN   string
	cardIssue string
}

func (f *addFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.kind, "kind", "login", "entry kind: login, note or card")
	fs.StringVar(&f.title, "title", "", "entry title (required)")
	fs.StringVar(&f.username, "username", "", "username or email")
	fs.StringVar(&f.url, "url", "", "site URL")
	fs.StringVar(&f.folder, "folder", "", "folder")
	fs.StringVar(&f.tags, "tags", "", "space-separated tags")
	fs.StringVar(&f.note, "note", "", "note body")
	fs.StringVar(&f.totp, "totp", "", "TOTP secret or otpauth:// URI")
	fs.BoolVar(&f.generate, "generate", false, "generate the password instead of prompting")
	fs.IntVar(&f.length, "length", 20, "generated password length")
	fs.StringVar(&f.password, "password", "", "password (avoid: visible in shell history and process listings)")
	fs.StringVar(&f.cardNum, "card-number", "", "card number")
	fs.StringVar(&f.cardHold, "card-holder", "", "cardholder name")
	fs.StringVar(&f.cardExp, "card-expiry", "", "expiry, MM/YY")
	fs.StringVar(&f.cardCVV, "card-cvv", "", "card security code")
	fs.StringVar(&f.cardPIN, "card-pin", "", "card PIN")
	fs.StringVar(&f.cardIssue, "card-issuer", "", "issuing bank")
}

type getFlags struct {
	copy     bool
	raw      bool
	reveal   bool
	asJSON   bool
	field    string
	clipWait bool
}

func (f *getFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&f.copy, "copy", false, "copy the password to the clipboard and clear it after the timeout")
	fs.BoolVar(&f.raw, "raw", false, "print only the password, with no trailing newline decoration")
	fs.BoolVar(&f.reveal, "reveal", false, "print the password to the terminal instead of masking it")
	fs.BoolVar(&f.asJSON, "json", false, "emit JSON")
	fs.StringVar(&f.field, "field", "", "print one field: password, username, url, note, totp")
	fs.BoolVar(&f.clipWait, "wait", true, "with --copy, stay running until the clipboard is cleared")
}

type listFlags struct {
	folder string
	tag    string
	kind   string
	asJSON bool
}

func (f *listFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.folder, "folder", "", "only entries in this folder")
	fs.StringVar(&f.tag, "tag", "", "only entries with this tag")
	fs.StringVar(&f.kind, "kind", "", "only entries of this kind")
	fs.BoolVar(&f.asJSON, "json", false, "emit JSON")
}

type editFlags struct {
	title    string
	username string
	url      string
	folder   string
	tags     string
	note     string
	totp     string
	password string
	generate bool
	length   int
	clear    string
}

func (f *editFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.title, "title", "", "new title")
	fs.StringVar(&f.username, "username", "", "new username")
	fs.StringVar(&f.url, "url", "", "new URL")
	fs.StringVar(&f.folder, "folder", "", "new folder")
	fs.StringVar(&f.tags, "tags", "", "replacement tags, space-separated")
	fs.StringVar(&f.note, "note", "", "new note")
	fs.StringVar(&f.totp, "totp", "", "new TOTP secret or otpauth:// URI")
	fs.StringVar(&f.password, "password", "", "new password (avoid: visible in process listings)")
	fs.BoolVar(&f.generate, "generate", false, "generate a new password")
	fs.IntVar(&f.length, "length", 20, "generated password length")
	fs.StringVar(&f.clear, "clear", "", "comma-separated fields to blank: note, totp, url, username")
}

type generateFlags struct {
	length     int
	count      int
	noUpper    bool
	noDigits   bool
	noSymbols  bool
	ambiguous  bool
	exclude    string
	passphrase int
	separator  string
	capitalize bool
	digit      bool
}

func (f *generateFlags) bind(fs *flag.FlagSet) {
	fs.IntVar(&f.length, "length", 20, "password length")
	fs.IntVar(&f.count, "count", 1, "how many to generate")
	fs.BoolVar(&f.noUpper, "no-upper", false, "omit uppercase letters")
	fs.BoolVar(&f.noDigits, "no-digits", false, "omit digits")
	fs.BoolVar(&f.noSymbols, "no-symbols", false, "omit symbols")
	fs.BoolVar(&f.ambiguous, "ambiguous", false, "allow the lookalike characters l I O 0 1")
	fs.StringVar(&f.exclude, "exclude", "", "characters to exclude")
	fs.IntVar(&f.passphrase, "words", 0, "generate a passphrase of N words instead")
	fs.StringVar(&f.separator, "separator", "-", "passphrase word separator")
	fs.BoolVar(&f.capitalize, "capitalize", false, "capitalise passphrase words")
	fs.BoolVar(&f.digit, "append-digit", false, "append a digit to the passphrase")
}

type totpFlags struct {
	copy   bool
	follow bool
}

func (f *totpFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&f.copy, "copy", false, "copy the code to the clipboard")
	fs.BoolVar(&f.follow, "follow", false, "keep printing codes until interrupted")
}

type checkFlags struct {
	all     bool
	enable  bool
	offline bool
}

func (f *checkFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&f.all, "all", false, "audit every entry instead of one")
	fs.BoolVar(&f.enable, "online", false, "allow the k-anonymity breach lookup (sends 5 hash characters)")
	fs.BoolVar(&f.offline, "offline", false, "force local-only analysis even if VAULT_HIBP is set")
}

type exportFlags struct {
	out          string
	iUnderstand  bool
	includeEmpty bool
}

func (f *exportFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.out, "out", "", "output file (default: stdout)")
	fs.BoolVar(&f.iUnderstand, "i-understand", false, "required: this writes every password in plaintext")
	fs.BoolVar(&f.includeEmpty, "include-empty", false, "include entries with no password")
}

type rotateFlags struct {
	n int
	r int
	p int
}

func (f *rotateFlags) bind(fs *flag.FlagSet) {
	fs.IntVar(&f.n, "N", 0, "new scrypt N (0 keeps the current value)")
	fs.IntVar(&f.r, "r", 0, "new scrypt r (0 keeps the current value)")
	fs.IntVar(&f.p, "p", 0, "new scrypt p (0 keeps the current value)")
}

type initFlags struct {
	n int
	r int
	p int
}

func (f *initFlags) bind(fs *flag.FlagSet) {
	fs.IntVar(&f.n, "N", 0, "scrypt N (0 uses the configured default)")
	fs.IntVar(&f.r, "r", 0, "scrypt r")
	fs.IntVar(&f.p, "p", 0, "scrypt p")
}

// flagsFor builds an empty flag set for `vault help <command>`.
func flagsFor(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	switch name {
	case "init":
		(&initFlags{}).bind(fs)
	case "add":
		(&addFlags{}).bind(fs)
	case "get":
		(&getFlags{}).bind(fs)
	case "list", "ls":
		(&listFlags{}).bind(fs)
	case "edit":
		(&editFlags{}).bind(fs)
	case "generate", "gen":
		(&generateFlags{}).bind(fs)
	case "totp":
		(&totpFlags{}).bind(fs)
	case "check":
		(&checkFlags{}).bind(fs)
	case "export":
		(&exportFlags{}).bind(fs)
	case "rotate-master":
		(&rotateFlags{}).bind(fs)
	default:
		return nil
	}
	return fs
}
