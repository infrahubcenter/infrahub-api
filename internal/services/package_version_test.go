package services

import "testing"

func TestCompareDebianVersions_SimpleUpstream(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.9", "1.10", -1}, // the classic lexical-comparison trap
		{"1.10", "1.9", 1},
		{"2.0.0", "1.9.9", 1},
	}
	for _, c := range cases {
		if got := CompareDebianVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareDebianVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareDebianVersions_Epoch(t *testing.T) {
	// An epoch always dominates, however small the upstream version looks.
	if CompareDebianVersions("1:1.0", "2.0") <= 0 {
		t.Error("1:1.0 should be greater than 2.0 (epoch dominates)")
	}
	if CompareDebianVersions("1:1.0", "1:0.9") <= 0 {
		t.Error("1:1.0 should be greater than 1:0.9")
	}
	if CompareDebianVersions("0:1.0", "1.0") != 0 {
		t.Error("explicit epoch 0 should equal no epoch")
	}
}

func TestCompareDebianVersions_Revision(t *testing.T) {
	if CompareDebianVersions("2.0.0-1", "2.0.0-2") >= 0 {
		t.Error("2.0.0-1 should be less than 2.0.0-2")
	}
	if CompareDebianVersions("2.0.0-2ubuntu1", "2.0.0-2") <= 0 {
		t.Error("2.0.0-2ubuntu1 should be greater than 2.0.0-2 (extra revision suffix)")
	}
	if CompareDebianVersions("1:2.4.57-1ubuntu1", "1:2.4.57-1ubuntu2") >= 0 {
		t.Error("1:2.4.57-1ubuntu1 should be less than 1:2.4.57-1ubuntu2")
	}
}

func TestCompareDebianVersions_Tilde(t *testing.T) {
	// ~ sorts before everything, including the empty string -- this is
	// exactly how Debian encodes pre-releases (1.2.3~rc1 < 1.2.3).
	if CompareDebianVersions("1.2.3~rc1", "1.2.3") >= 0 {
		t.Error("1.2.3~rc1 should be less than 1.2.3 (tilde sorts first)")
	}
	if CompareDebianVersions("1.2.3~rc1", "1.2.3~rc2") >= 0 {
		t.Error("1.2.3~rc1 should be less than 1.2.3~rc2")
	}
	if CompareDebianVersions("1.0~beta", "1.0~~") <= 0 {
		t.Error("1.0~beta should be greater than 1.0~~ (~ alone sorts before ~beta)")
	}
}

func TestCompareDebianVersions_LettersBeforeNonLetters(t *testing.T) {
	// dpkg: letters sort before non-letter, non-~ characters.
	if CompareDebianVersions("1.0a", "1.0+") >= 0 {
		t.Error("1.0a should sort before 1.0+ (letters before punctuation)")
	}
}

func TestCompareDebianVersions_Equal(t *testing.T) {
	if CompareDebianVersions("1:2.4.57-1ubuntu1", "1:2.4.57-1ubuntu1") != 0 {
		t.Error("identical versions must compare equal")
	}
}

// --- RPM ---

func TestCompareRPMVersions_Simple(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"3.0.7", "3.0.8", -1},
		{"1.9", "1.10", -1}, // same lexical trap as Debian
		{"5.10", "5.9", 1},
	}
	for _, c := range cases {
		if got := CompareRPMVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareRPMVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRPMVersions_Epoch(t *testing.T) {
	if CompareRPMVersions("1:1.0", "2.0") <= 0 {
		t.Error("1:1.0 should be greater than 2.0 (epoch dominates)")
	}
}

func TestCompareRPMVersions_AlphaVsNumericSegment(t *testing.T) {
	// rpmvercmp: a numeric segment always outranks an alpha segment at the
	// same position ("1.0a" < "1.0.1" because "a" vs a missing/absent
	// numeric segment... more precisely: comparing "a" against "1" -- numeric wins).
	if CompareRPMVersions("1.a", "1.1") >= 0 {
		t.Error("1.a should be less than 1.1 (alpha segment loses to numeric)")
	}
}

func TestCompareRPMVersions_LeadingZerosIgnored(t *testing.T) {
	if CompareRPMVersions("1.001", "1.1") != 0 {
		t.Error("leading zeros in a numeric segment must not affect comparison")
	}
	if CompareRPMVersions("1.05", "1.5") != 0 {
		t.Error("1.05 should equal 1.5 numerically")
	}
}

func TestCompareRPMVersions_Tilde(t *testing.T) {
	if CompareRPMVersions("1.0~rc1", "1.0") >= 0 {
		t.Error("1.0~rc1 should be less than 1.0")
	}
}

func TestCompareRPMFull_ReleaseBreaksTie(t *testing.T) {
	// Same version, different release -- release must determine ordering
	// (spec §28's openssl 3.0.7-25.el9_2 example).
	if CompareRPMFull("3.0.7", "25.el9_2", "3.0.7", "26.el9_2") >= 0 {
		t.Error("release 25 should be less than release 26 for the same version")
	}
	if CompareRPMFull("3.0.7", "25.el9_2", "3.0.7", "25.el9_2") != 0 {
		t.Error("identical version+release must compare equal")
	}
	if CompareRPMFull("3.0.7", "25.el9_2", "3.0.8", "1.el9") >= 0 {
		t.Error("a higher version must win even with a lower release")
	}
}

func TestCompareRPMVersions_Equal(t *testing.T) {
	if CompareRPMVersions("3.0.7", "3.0.7") != 0 {
		t.Error("identical versions must compare equal")
	}
}

func TestCompareRPMVersions_DifferentLength(t *testing.T) {
	// rpmvercmp: whichever string has "more" left after the other is
	// exhausted (having consumed everything comparable) is greater --
	// e.g. "1.0" vs "1.0.1".
	if CompareRPMVersions("1.0", "1.0.1") >= 0 {
		t.Error("1.0 should be less than 1.0.1")
	}
}
