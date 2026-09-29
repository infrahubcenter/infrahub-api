package services

import "testing"

func TestNormalizeQuery_LiteralsReplaced(t *testing.T) {
	a := NormalizeQuery("SELECT * FROM orders WHERE id = 100")
	b := NormalizeQuery("SELECT * FROM orders WHERE id = 200")
	if a != b {
		t.Fatalf("normalized forms differ: %q vs %q, want identical (spec #9)", a, b)
	}
	if a != "SELECT * FROM orders WHERE id = ?" {
		t.Errorf("normalized = %q, want 'SELECT * FROM orders WHERE id = ?'", a)
	}
}

func TestNormalizeQuery_StringLiteralsReplaced(t *testing.T) {
	a := NormalizeQuery("SELECT * FROM users WHERE email = 'alice@example.com'")
	b := NormalizeQuery("SELECT * FROM users WHERE email = 'bob@example.com'")
	if a != b {
		t.Fatalf("normalized forms with different string literals differ: %q vs %q", a, b)
	}
	if a != "SELECT * FROM users WHERE email = ?" {
		t.Errorf("normalized = %q, want literal stripped", a)
	}
}

func TestNormalizeQuery_WhitespaceCollapsed(t *testing.T) {
	got := NormalizeQuery("SELECT  *\nFROM   t\t WHERE x = 1")
	want := "SELECT * FROM t WHERE x = ?"
	if got != want {
		t.Errorf("normalized = %q, want %q", got, want)
	}
}

func TestFingerprint_StableForSameNormalizedForm(t *testing.T) {
	n1 := NormalizeQuery("SELECT * FROM users WHERE id = 1")
	n2 := NormalizeQuery("SELECT * FROM users WHERE id = 999")
	if Fingerprint(n1) != Fingerprint(n2) {
		t.Error("fingerprints of the same normalized structure must match regardless of literal values")
	}
}

func TestFingerprint_DiffersForDifferentQueries(t *testing.T) {
	f1 := Fingerprint(NormalizeQuery("SELECT * FROM users WHERE id = 1"))
	f2 := Fingerprint(NormalizeQuery("SELECT * FROM orders WHERE id = 1"))
	if f1 == f2 {
		t.Error("fingerprints of genuinely different query structures must differ")
	}
}

func TestFingerprint_NeverContainsRawInput(t *testing.T) {
	f := Fingerprint("SELECT * FROM users WHERE ssn = '123-45-6789'")
	if len(f) != 64 { // hex-encoded SHA-256
		t.Fatalf("fingerprint length = %d, want 64 (hex SHA-256)", len(f))
	}
	for _, c := range f {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("fingerprint contains non-hex character %q -- must never leak raw input", c)
		}
	}
}

func TestTruncateQueryText(t *testing.T) {
	if got := TruncateQueryText("short", 100); got != "short" {
		t.Errorf("short string should pass through unchanged, got %q", got)
	}
	long := "SELECT " + string(make([]byte, 5000))
	if got := TruncateQueryText(long, 10); len(got) != 10 {
		t.Errorf("truncated length = %d, want 10", len(got))
	}
}
