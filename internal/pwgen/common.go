package pwgen

// CommonPasswords is a frequency-ordered slice of passwords that appear at the top of
// every credential dump. Order is the point: index 0 is what an attacker tries first, so
// the estimator can price "password" at 1 guess rather than at 26^8.
//
// It is short — 120 entries against the millions in a real cracking list — which means
// Estimate will overrate a password that is common but not listed here. That is a data
// limitation, not a design one, and the README says so rather than implying full coverage.
var CommonPasswords = []string{
	"123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567",
	"111111", "1234567890", "123123", "abc123", "1234", "password1", "iloveyou",
	"1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine", "princess",
	"letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop",
	"superman", "asdfghjkl", "trustno1", "football", "baseball", "welcome",
	"jesus", "ninja", "mustang", "password123", "admin", "shadow", "master",
	"michael", "jennifer", "jordan", "harley", "hunter", "ranger", "buster",
	"soccer", "hockey", "killer", "george", "sexy", "andrew", "charlie",
	"thomas", "robert", "tigger", "cheese", "starwars", "computer", "corvette",
	"matrix", "falcon", "cookie", "maggie", "biteme", "banana", "chelsea",
	"summer", "internet", "service", "canada", "hello", "ranger1", "hammer",
	"silver", "222222", "88888888", "anthony", "justin", "test", "love",
	"secret", "freedom", "whatever", "nicole", "chicken", "pepper", "daniel",
	"access", "flower", "555555", "lovely", "7777777", "888888", "666666",
	"batman", "andrea", "purple", "amanda", "orange", "diamond", "player",
	"scooter", "dallas", "cowboy", "yankees", "eagles", "phoenix", "guitar",
	"samsung", "google", "changeme", "passw0rd", "p@ssword", "qazwsx",
	"asdf1234", "letmein1", "welcome1", "admin123", "root", "toor",
}
