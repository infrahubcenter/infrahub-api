package services

import (
	"testing"
	"time"
)

// --- dpkg-query ---

func TestParseDpkgQuery_Normal(t *testing.T) {
	out := "nginx\t1.24.0-2ubuntu7\tamd64\n" +
		"openssl\t3.0.13-0ubuntu3\tamd64\n" +
		"libfoo\t1.0-1\tamd64\n" +
		"libfoo\t1.0-1\ti386\n"
	pkgs := ParseDpkgQuery(out)
	if len(pkgs) != 4 {
		t.Fatalf("got %d packages, want 4", len(pkgs))
	}
	if pkgs[0].Name != "nginx" || pkgs[0].Version != "1.24.0-2ubuntu7" || pkgs[0].Architecture != "amd64" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
}

func TestParseDpkgQuery_MultiArchNotCollapsed(t *testing.T) {
	out := "libfoo\t1.0-1\tamd64\nlibfoo\t1.0-1\ti386\n"
	pkgs := ParseDpkgQuery(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (libfoo:amd64 and libfoo:i386 must stay distinct)", len(pkgs))
	}
	if pkgs[0].Architecture == pkgs[1].Architecture {
		t.Error("expected two different architectures")
	}
}

func TestParseDpkgQuery_EmptyAndMalformed(t *testing.T) {
	if pkgs := ParseDpkgQuery(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	out := "\nnginx\t1.24.0\tamd64\nmalformed-line-no-tabs\n\t\t\n"
	pkgs := ParseDpkgQuery(out)
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (only the well-formed line)", len(pkgs))
	}
}

// --- apt list --upgradable ---

func TestParseAptUpgradable_Normal(t *testing.T) {
	out := `Listing...
nginx/jammy-updates 1.26.2-0ubuntu1 amd64 [upgradable from: 1.24.0-2ubuntu7]
openssl/jammy-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3]
`
	updates := ParseAptUpgradable(out)
	if len(updates) != 2 {
		t.Fatalf("got %d updates, want 2", len(updates))
	}
	if updates[0].Name != "nginx" || updates[0].AvailableVersion != "1.26.2-0ubuntu1" {
		t.Errorf("updates[0] = %+v", updates[0])
	}
	if updates[0].SecurityStatus != SecurityUnknown {
		t.Errorf("nginx (jammy-updates, no -security) SecurityStatus = %v, want UNKNOWN", updates[0].SecurityStatus)
	}
	if updates[1].SecurityStatus != SecurityConfirmed {
		t.Errorf("openssl (jammy-security) SecurityStatus = %v, want CONFIRMED", updates[1].SecurityStatus)
	}
}

func TestParseAptUpgradable_EmptyMeansNoUpdates(t *testing.T) {
	out := "Listing...\n"
	if updates := ParseAptUpgradable(out); len(updates) != 0 {
		t.Errorf("got %d updates, want 0", len(updates))
	}
}

func TestParseAptUpgradable_NeverGuessesSecurityFromName(t *testing.T) {
	// A package literally named "security-tools" with no -security pocket
	// in its release info must not be misclassified.
	out := "security-tools/jammy-updates 2.0-1 amd64 [upgradable from: 1.0-1]\n"
	updates := ParseAptUpgradable(out)
	if len(updates) != 1 {
		t.Fatalf("got %d updates, want 1", len(updates))
	}
	if updates[0].SecurityStatus == SecurityConfirmed {
		t.Error("security_status must never be inferred from the package name")
	}
}

// --- rpm -qa ---

func TestParseRPMQA_Normal(t *testing.T) {
	out := "openssl\t1:3.0.7-25.el9_2\tx86_64\tUtilities for creating and checking certificates\n" +
		"kernel\t5.14.0-362.el9\tx86_64\tThe Linux kernel\n"
	pkgs := ParseRPMQA(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "1:3.0.7-25.el9_2" || pkgs[0].Architecture != "x86_64" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
	if pkgs[0].Description == "" {
		t.Error("expected a non-empty description from %{SUMMARY}")
	}
}

func TestParseRPMQA_WithInstallTime(t *testing.T) {
	out := "openssl\t1:3.0.7-25.el9_2\tx86_64\tUtilities\t1690000000\n" +
		"kernel\t5.14.0-362.el9\tx86_64\tThe Linux kernel\t0\n"
	pkgs := ParseRPMQA(out)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].InstalledAt == nil {
		t.Fatal("expected InstalledAt to be parsed from %{INSTALLTIME}")
	}
	want := time.Unix(1690000000, 0).UTC()
	if !pkgs[0].InstalledAt.Equal(want) {
		t.Errorf("InstalledAt = %v, want %v", pkgs[0].InstalledAt, want)
	}
	// An INSTALLTIME of 0 (or unparseable) must never fabricate a
	// timestamp -- nil so callers fall back to discovery time instead.
	if pkgs[1].InstalledAt != nil {
		t.Errorf("expected nil InstalledAt for a zero INSTALLTIME, got %v", pkgs[1].InstalledAt)
	}
}

func TestParseDpkgInstallTimes(t *testing.T) {
	out := "1690000000 /var/lib/dpkg/info/docker-ce.list\n" +
		"1690000100 /var/lib/dpkg/info/libc6:amd64.list\n" +
		"not a valid line\n" +
		"\n"
	times := ParseDpkgInstallTimes(out)
	if len(times) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(times), times)
	}
	if got, ok := times["docker-ce"]; !ok || !got.Equal(time.Unix(1690000000, 0).UTC()) {
		t.Errorf("docker-ce install time = %v, ok=%v", got, ok)
	}
	// The ":amd64" multi-arch suffix must be stripped so it joins against
	// ParseDpkgQuery's bare package name.
	if got, ok := times["libc6"]; !ok || !got.Equal(time.Unix(1690000100, 0).UTC()) {
		t.Errorf("libc6 install time = %v, ok=%v", got, ok)
	}
}

func TestParseRPMQA_MissingSummaryStillParses(t *testing.T) {
	out := "openssl\t3.0.7-25.el9_2\tx86_64\n"
	pkgs := ParseRPMQA(out)
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Description != "" {
		t.Errorf("Description = %q, want empty", pkgs[0].Description)
	}
}

func TestParseRPMQA_EmptyAndMalformed(t *testing.T) {
	if pkgs := ParseRPMQA(""); len(pkgs) != 0 {
		t.Errorf("empty input produced %d packages", len(pkgs))
	}
	out := "\nopenssl\t3.0.7-25.el9_2\tx86_64\tSummary\nmalformed\n"
	pkgs := ParseRPMQA(out)
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
}

// --- dnf/yum check-update ---

const sampleCheckUpdate = `Last metadata expiration check: 0:12:34 ago on Mon 01 Jan 2026.
openssl.x86_64                     1:3.0.7-26.el9_2                  baseos
kernel.x86_64                      5.14.0-362.1.el9                  baseos

Obsoleting Packages
foo.x86_64                         2.0-1.el9                          appstream
`

func TestParseCheckUpdate_Normal(t *testing.T) {
	updates := ParseCheckUpdate(sampleCheckUpdate, nil)
	if len(updates) != 3 {
		t.Fatalf("got %d updates, want 3, got %+v", len(updates), updates)
	}
	if updates[0].Name != "openssl" || updates[0].Architecture != "x86_64" {
		t.Errorf("updates[0] = %+v", updates[0])
	}
	if updates[0].AvailableVersion != "1:3.0.7" || updates[0].Release != "26.el9_2" {
		t.Errorf("updates[0] version/release = %q/%q, want 1:3.0.7/26.el9_2", updates[0].AvailableVersion, updates[0].Release)
	}
}

func TestParseCheckUpdate_SkipsHeaderAndSectionLines(t *testing.T) {
	updates := ParseCheckUpdate(sampleCheckUpdate, nil)
	for _, u := range updates {
		if u.Name == "" {
			t.Errorf("a header/section line was incorrectly parsed as a package: %+v", u)
		}
	}
}

func TestParseCheckUpdate_SecurityClassification(t *testing.T) {
	securityNames := map[string]bool{"openssl.x86_64": true}
	updates := ParseCheckUpdate(sampleCheckUpdate, securityNames)
	byName := map[string]AvailableUpdate{}
	for _, u := range updates {
		byName[u.Name] = u
	}
	if byName["openssl"].SecurityStatus != SecurityConfirmed {
		t.Errorf("openssl SecurityStatus = %v, want CONFIRMED", byName["openssl"].SecurityStatus)
	}
	if byName["kernel"].SecurityStatus != SecurityUnknown {
		t.Errorf("kernel SecurityStatus = %v, want UNKNOWN (not in the security set, but that's not proof either way)", byName["kernel"].SecurityStatus)
	}
}

func TestParseCheckUpdate_NilSecurityMapMeansAllUnknown(t *testing.T) {
	updates := ParseCheckUpdate(sampleCheckUpdate, nil)
	for _, u := range updates {
		if u.SecurityStatus != SecurityUnknown {
			t.Errorf("%s SecurityStatus = %v, want UNKNOWN when security info wasn't queried", u.Name, u.SecurityStatus)
		}
	}
}

func TestParseCheckUpdate_EmptyMeansNoUpdates(t *testing.T) {
	if updates := ParseCheckUpdate("Last metadata expiration check: 0:01:00 ago.\n", nil); len(updates) != 0 {
		t.Errorf("got %d updates, want 0", len(updates))
	}
}

func TestParseCheckUpdateSecurityNames(t *testing.T) {
	names := ParseCheckUpdateSecurityNames("openssl.x86_64   1:3.0.7-26.el9_2   baseos\n")
	if !names["openssl.x86_64"] {
		t.Error("expected openssl.x86_64 in the security set")
	}
	if len(names) != 1 {
		t.Errorf("got %d names, want 1", len(names))
	}
}
