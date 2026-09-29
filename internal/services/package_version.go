package services

import "strings"

// This file implements package-manager-aware version comparison (Step 7
// spec §26-28): plain string/lexical comparison is explicitly wrong for
// package versions ("1.10" < "1.9" lexically, but 1.10 is the newer
// version) so every comparison here follows each ecosystem's own
// documented algorithm instead.

// --- Debian/dpkg version comparison (spec §27) ---

// CompareDebianVersions compares two Debian package version strings
// using dpkg's documented algorithm (Debian Policy Manual §5.6.12):
// "[epoch:]upstream_version[-debian_revision]". Returns -1, 0, or 1.
//
// Known limitation: does not implement dpkg's "obsolete" alternate
// epoch/version separators or any vendor-specific extensions beyond the
// documented algorithm.
func CompareDebianVersions(a, b string) int {
	epochA, restA := splitDebianEpoch(a)
	epochB, restB := splitDebianEpoch(b)
	if epochA != epochB {
		return compareInt(epochA, epochB)
	}

	upstreamA, revisionA := splitDebianRevision(restA)
	upstreamB, revisionB := splitDebianRevision(restB)

	if c := compareDebianPart(upstreamA, upstreamB); c != 0 {
		return c
	}
	return compareDebianPart(revisionA, revisionB)
}

func splitDebianEpoch(v string) (epoch int, rest string) {
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		epoch = parseIntOrZero(v[:idx])
		return epoch, v[idx+1:]
	}
	return 0, v
}

// splitDebianRevision splits at the LAST hyphen -- everything before is
// the upstream version (which may itself contain hyphens), everything
// after is the debian_revision. No hyphen means an implicit "0" revision.
func splitDebianRevision(v string) (upstream, revision string) {
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		return v[:idx], v[idx+1:]
	}
	return v, "0"
}

// compareDebianPart implements the alternating non-digit/digit comparison
// dpkg uses for both the upstream_version and debian_revision parts.
func compareDebianPart(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		na := debianNonDigitPrefixLen(a)
		nb := debianNonDigitPrefixLen(b)
		if c := compareDebianNonDigit(a[:na], b[:nb]); c != 0 {
			return c
		}
		a, b = a[na:], b[nb:]

		da := digitPrefixLen(a)
		db := digitPrefixLen(b)
		numA := parseIntOrZero(a[:da])
		numB := parseIntOrZero(b[:db])
		if numA != numB {
			return compareInt(numA, numB)
		}
		a, b = a[da:], b[db:]
	}
	return 0
}

func debianNonDigitPrefixLen(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return i
		}
	}
	return len(s)
}

func digitPrefixLen(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return i
		}
	}
	return len(s)
}

// compareDebianNonDigit compares two non-digit runs character by
// character using dpkg's order: '~' sorts before everything (even the
// empty/end-of-string), end-of-string sorts before everything else,
// letters sort before all other characters, and within each of those
// buckets plain ASCII order applies.
func compareDebianNonDigit(a, b string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ca, cb byte
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		if ca == cb {
			continue
		}
		return compareInt(debianCharOrder(ca), debianCharOrder(cb))
	}
	return 0
}

func debianCharOrder(c byte) int {
	switch {
	case c == '~':
		return -2
	case c == 0: // past end of string
		return -1
	case isAsciiLetter(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func isAsciiLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// --- RPM version comparison (spec §28) ---

// CompareRPMVersions compares two RPM "version-release" (or just
// "version") strings using the classic rpmvercmp algorithm, plus '~'
// pre-release support (RPM >= 4.10). The epoch, when present
// ("epoch:version"), is compared first and numerically, exactly like
// Debian's.
//
// Known limitation: does not implement '^' (post-release, RPM >= 4.15) --
// a rare, newer extension; every other documented rpmvercmp behavior is
// implemented.
func CompareRPMVersions(a, b string) int {
	epochA, restA := splitDebianEpoch(a) // "epoch:rest" -- identical syntax to Debian's
	epochB, restB := splitDebianEpoch(b)
	if epochA != epochB {
		return compareInt(epochA, epochB)
	}
	return rpmVerCmp(restA, restB)
}

// CompareRPMFull compares two full "version-release" strings component by
// component -- version first, release only as a tiebreaker (spec §28:
// "do not compare only 3.0.7 if release information determines
// ordering").
func CompareRPMFull(versionA, releaseA, versionB, releaseB string) int {
	if c := CompareRPMVersions(versionA, versionB); c != 0 {
		return c
	}
	return rpmVerCmp(releaseA, releaseB)
}

func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	for len(a) > 0 || len(b) > 0 {
		a = strings.TrimLeftFunc(a, isRPMSeparator)
		b = strings.TrimLeftFunc(b, isRPMSeparator)

		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			aTilde := strings.HasPrefix(a, "~")
			bTilde := strings.HasPrefix(b, "~")
			if aTilde && bTilde {
				a, b = a[1:], b[1:]
				continue
			}
			if aTilde {
				return -1
			}
			return 1
		}

		if a == "" || b == "" {
			break
		}

		var segA, segB string
		var numeric bool
		if isAsciiDigit(a[0]) {
			la := digitPrefixLen(a)
			segA = strings.TrimLeft(a[:la], "0")
			a = a[la:]
			numeric = true
		} else {
			la := rpmAlphaPrefixLen(a)
			segA = a[:la]
			a = a[la:]
		}
		if numeric {
			if !isAsciiDigit(firstByteOrZero(b)) {
				// numeric segment always outranks an alpha segment.
				return 1
			}
			lb := digitPrefixLen(b)
			segB = strings.TrimLeft(b[:lb], "0")
			b = b[lb:]
			if len(segA) != len(segB) {
				return compareInt(len(segA), len(segB))
			}
		} else {
			if isAsciiDigit(firstByteOrZero(b)) {
				return -1
			}
			lb := rpmAlphaPrefixLen(b)
			segB = b[:lb]
			b = b[lb:]
		}
		if segA != segB {
			if segA < segB {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	default:
		return 1
	}
}

func isRPMSeparator(r rune) bool {
	return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '~')
}

func isAsciiDigit(c byte) bool { return c >= '0' && c <= '9' }

func firstByteOrZero(s string) byte {
	if len(s) == 0 {
		return 0
	}
	return s[0]
}

func rpmAlphaPrefixLen(s string) int {
	for i := 0; i < len(s); i++ {
		if isAsciiDigit(s[i]) || s[i] == '~' {
			return i
		}
	}
	return len(s)
}

// --- shared helpers ---

func parseIntOrZero(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
