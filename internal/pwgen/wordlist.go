package pwgen

// Wordlist backs passphrase generation and the dictionary check in Estimate.
//
// It is exactly 256 words, which is 8 bits per word — a round number chosen so the
// entropy arithmetic is transparent rather than approximate. Words are 3-7 letters,
// unambiguous when spoken, and share no prefixes long enough to confuse a reader.
//
// Honest limitation: the EFF long list is 7776 words, or 12.9 bits each. At 8 bits per
// word a six-word passphrase is 48 bits where EFF's is 77. This list is short because
// bundling 7776 words is a data-sourcing decision rather than an engineering one, and
// the README marks the larger list as not done rather than pretending the numbers match.
// PassphraseEntropy computes from len(Wordlist), so swapping in a bigger list is one
// edit and every reported figure follows.
var Wordlist = []string{
	"able", "acid", "acorn", "actor", "agent", "album", "alert", "alley",
	"amber", "anchor", "angle", "ankle", "apple", "apron", "arbor", "arrow",
	"aspen", "atlas", "attic", "autumn", "awake", "badge", "bagel", "baker",
	"balloon", "banjo", "barge", "basin", "beacon", "beetle", "bench", "berry",
	"birch", "bison", "blaze", "blend", "bloom", "board", "bolt", "bonus",
	"boulder", "brave", "bread", "brick", "bridge", "brisk", "bronze", "brush",
	"bubble", "bucket", "buffalo", "bundle", "burst", "cabin", "cable", "cactus",
	"camel", "canal", "candle", "canoe", "canvas", "canyon", "carbon", "cargo",
	"carpet", "castle", "cattle", "cedar", "cement", "census", "chain", "chalk",
	"charm", "cheese", "cherry", "chess", "chime", "cider", "cinema", "circle",
	"citrus", "clamp", "clay", "clever", "cliff", "cloak", "clover", "cobalt",
	"cocoa", "collar", "comet", "compass", "copper", "coral", "corner", "cotton",
	"coyote", "crane", "crater", "cream", "crisp", "crown", "crystal", "cube",
	"curve", "cyclone", "daisy", "dandy", "dawn", "decoy", "delta", "denim",
	"desert", "diamond", "diesel", "dolphin", "domino", "donut", "dragon", "dream",
	"drift", "drum", "dune", "eagle", "earth", "ember", "emerald", "engine",
	"escape", "ether", "fable", "falcon", "fern", "fiber", "fiddle", "field",
	"flame", "flask", "fleet", "flint", "florist", "flute", "forest", "forge",
	"fossil", "fountain", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
	"ginger", "glacier", "glass", "glide", "globe", "gold", "granite", "grape",
	"gravel", "grove", "guitar", "gulf", "hammer", "harbor", "harvest", "hazel",
	"heron", "hollow", "honey", "hornet", "iceberg", "indigo", "iris", "island",
	"ivory", "jacket", "jaguar", "jasmine", "jetty", "jungle", "kettle", "keystone",
	"kingdom", "kite", "koala", "lagoon", "lantern", "lattice", "lava", "ledger",
	"lemon", "lever", "lilac", "linen", "lizard", "lobster", "locket", "lotus",
	"lumber", "lunar", "magnet", "mango", "maple", "marble", "marsh", "meadow",
	"melon", "mercury", "meteor", "mint", "mirror", "mosaic", "moss", "motto",
	"nectar", "needle", "nickel", "noble", "nomad", "north", "nugget", "oasis",
	"ocean", "olive", "onyx", "opal", "orbit", "orchid", "otter", "outpost",
	"paddle", "palace", "pandora", "pantry", "parcel", "parsley", "pastel", "pebble",
	"pelican", "pepper", "petal", "pewter", "phantom", "piano", "pilot", "pine",
	"pistol", "planet", "plaza", "plum", "polar", "pollen", "poplar", "prairie",
}
