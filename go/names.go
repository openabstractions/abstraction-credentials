package credentials

// ValidName reports whether s is a credential name: 1 to 64 ASCII letters,
// digits, '_', '.' or '-'. It is the one validator every caller uses.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// ValidConsumer reports whether s is a consumer contract name such as
// abstraction.download/http-execution@1.
func ValidConsumer(s string) bool { return consumerPattern.MatchString(s) }

// ValidKind reports whether s is a well-formed credential kind: a simple kind
// this provider supports, or an owned kind <owner>/<name>@<version>, which may
// still be unsupported.
func ValidKind(s string) bool {
	for _, kind := range SupportedKinds {
		if s == kind {
			return true
		}
	}
	return ownedKind.MatchString(s)
}
