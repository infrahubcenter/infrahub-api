package services

import (
	"os"
	"testing"
	"time"
)

func TestParseLicenseDefaultsToCommunity(t *testing.T) {
	for _, key := range []string{"", "  ", "not-a-key", "IHC1.abc", "IHC1.eyJwbGFuIjoiZW50ZXJwcmlzZSJ9.AAAA"} {
		lic := ParseLicense(key, time.Now())
		if lic.Plan.ID != "community" {
			t.Fatalf("key %q: got plan %q, want community", key, lic.Plan.ID)
		}
	}
	if ParseLicense("", time.Now()).Status != "community" {
		t.Fatal("empty key should report the community status")
	}
	if ParseLicense("IHC1.abc.def", time.Now()).Status != "invalid" {
		t.Fatal("a forged key should report invalid")
	}
}

func TestCommunityLimits(t *testing.T) {
	c := Plans["community"]
	want := map[LimitKind]int{LimitUsers: 1, LimitVMs: 2, LimitDatabases: 1, LimitObjectStorage: 1, LimitDockerHosts: 1, LimitK8sClusters: 1}
	for k, v := range want {
		if c.Limits[k] != v {
			t.Errorf("community %s = %d, want %d", k, c.Limits[k], v)
		}
	}
	if c.CapRetention(30, false) != 3 || c.CapRetention(2, false) != 2 {
		t.Error("community metrics retention should be capped at 3 days")
	}
	if Plans["enterprise"].CapRetention(365, false) != 365 {
		t.Error("enterprise retention should not be capped")
	}
}

// A real key issued with scripts/issue-license.mjs, passed in by whoever
// runs the test (the signing key never lives in this repository).
func TestParseIssuedLicense(t *testing.T) {
	key := os.Getenv("INFRAHUB_TEST_LICENSE_KEY")
	if key == "" {
		t.Skip("set INFRAHUB_TEST_LICENSE_KEY to a key issued for plan team, expiring 2099-12-31")
	}
	lic := ParseLicense(key, time.Now())
	if lic.Status != "active" || lic.Plan.ID != "team" {
		t.Fatalf("got status %q plan %q (%s)", lic.Status, lic.Plan.ID, lic.Error)
	}
	if exp := ParseLicense(key, time.Date(2100, 1, 2, 0, 0, 0, 0, time.UTC)); exp.Status != "expired" || exp.Plan.ID != "community" {
		t.Fatalf("after expiry: got status %q plan %q", exp.Status, exp.Plan.ID)
	}
	tampered := key[:len(key)-3] + "AAA"
	if ParseLicense(tampered, time.Now()).Plan.ID != "community" {
		t.Fatal("tampered key must fall back to community")
	}
}
