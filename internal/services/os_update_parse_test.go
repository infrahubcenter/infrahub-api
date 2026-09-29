package services

import "testing"

func TestParseOSReleaseFull_Ubuntu(t *testing.T) {
	out := `NAME="Ubuntu"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
VERSION_ID="24.04"
VERSION_CODENAME=noble`
	info, ok := ParseOSReleaseFull(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if info.Name != "Ubuntu" || info.ID != "ubuntu" || info.VersionID != "24.04" || info.VersionCodename != "noble" {
		t.Errorf("info = %+v", info)
	}
	if info.Version != "24.04.3 LTS (Noble Numbat)" {
		t.Errorf("Version = %q", info.Version)
	}
}

func TestParseOSReleaseFull_Empty(t *testing.T) {
	if _, ok := ParseOSReleaseFull(""); ok {
		t.Error("expected ok=false for empty input")
	}
}

func TestReleaseChannel_UbuntuLTS(t *testing.T) {
	if got := ReleaseChannel("ubuntu", "24.04.3 LTS (Noble Numbat)"); got != "LTS" {
		t.Errorf("got %q, want LTS", got)
	}
}

func TestReleaseChannel_UbuntuNonLTS(t *testing.T) {
	if got := ReleaseChannel("ubuntu", "24.10 (Oracular Oriole)"); got != "non-LTS" {
		t.Errorf("got %q, want non-LTS", got)
	}
}

func TestReleaseChannel_NonUbuntu_NeverFabricated(t *testing.T) {
	if got := ReleaseChannel("debian", "12 (bookworm)"); got != "unknown" {
		t.Errorf("got %q, want unknown (no real evidence for non-Ubuntu distros)", got)
	}
	if got := ReleaseChannel("rhel", "9.4 (Plow)"); got != "unknown" {
		t.Errorf("got %q, want unknown", got)
	}
}

func TestParseDoReleaseUpgradeCheck_Available(t *testing.T) {
	out := "Checking for a new Ubuntu release\nNew release '24.04' available.\nRun 'do-release-upgrade' to upgrade to it.\n"
	check := ParseDoReleaseUpgradeCheck(out)
	if !check.Available || check.NewRelease != "24.04" {
		t.Errorf("check = %+v", check)
	}
}

func TestParseDoReleaseUpgradeCheck_NoneAvailable(t *testing.T) {
	out := "Checking for a new Ubuntu release\nNo new release found.\n"
	check := ParseDoReleaseUpgradeCheck(out)
	if check.Available {
		t.Errorf("check = %+v, want Available=false", check)
	}
}

func TestParseDoReleaseUpgradeCheck_EmptyOrMalformed(t *testing.T) {
	if check := ParseDoReleaseUpgradeCheck(""); check.Available {
		t.Error("expected Available=false for empty output")
	}
	if check := ParseDoReleaseUpgradeCheck("command not found"); check.Available {
		t.Error("expected Available=false when the tool doesn't exist")
	}
}

func TestParseDebianRebootCheck_Required(t *testing.T) {
	out := "REQUIRED\nlinux-image-6.8.0-40-generic\nlibssl3\n"
	check, ok := ParseDebianRebootCheck(out)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !check.Required {
		t.Error("Required = false, want true")
	}
	if len(check.Packages) != 2 || check.Packages[0] != "linux-image-6.8.0-40-generic" || check.Packages[1] != "libssl3" {
		t.Errorf("Packages = %v", check.Packages)
	}
}

func TestParseDebianRebootCheck_NotRequired(t *testing.T) {
	check, ok := ParseDebianRebootCheck("NOT_REQUIRED\n")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if check.Required {
		t.Error("Required = true, want false")
	}
	if len(check.Packages) != 0 {
		t.Errorf("Packages = %v, want empty", check.Packages)
	}
}

func TestParseDebianRebootCheck_RequiredNoPackagesFile(t *testing.T) {
	check, ok := ParseDebianRebootCheck("REQUIRED\n")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !check.Required {
		t.Error("Required = false, want true")
	}
	if len(check.Packages) != 0 {
		t.Errorf("Packages = %v, want empty (no .pkgs file existed)", check.Packages)
	}
}

func TestParseDebianRebootCheck_MalformedNeverGuessed(t *testing.T) {
	if _, ok := ParseDebianRebootCheck(""); ok {
		t.Error("expected ok=false for empty/unexpected output -- must never guess REQUIRED or NOT_REQUIRED")
	}
	if _, ok := ParseDebianRebootCheck("something unexpected\n"); ok {
		t.Error("expected ok=false for unrecognized first line")
	}
}

func TestIsKernelPackageName_APT(t *testing.T) {
	cases := map[string]bool{
		"linux-image-6.8.0-40-generic": true,
		"linux-image-generic":          false, // meta-package, no specific version
		"linux-headers-6.8.0-40":       false,
		"nginx":                        false,
	}
	for name, want := range cases {
		if got := IsKernelPackageName(name, PMTypeAPT); got != want {
			t.Errorf("IsKernelPackageName(%q, APT) = %v, want %v", name, got, want)
		}
	}
}

func TestIsKernelPackageName_RPM(t *testing.T) {
	cases := map[string]bool{
		"kernel":       true,
		"kernel-core":  true,
		"kernel-devel": false,
		"nginx":        false,
	}
	for name, want := range cases {
		if got := IsKernelPackageName(name, PMTypeDNF); got != want {
			t.Errorf("IsKernelPackageName(%q, DNF) = %v, want %v", name, got, want)
		}
		if got := IsKernelPackageName(name, PMTypeYUM); got != want {
			t.Errorf("IsKernelPackageName(%q, YUM) = %v, want %v", name, got, want)
		}
	}
}

func TestIsKernelPackageName_Unsupported(t *testing.T) {
	if IsKernelPackageName("kernel", PMTypeUnsupported) {
		t.Error("expected false for PMTypeUnsupported")
	}
}

func TestExtractKernelVersion_APT(t *testing.T) {
	v, ok := ExtractKernelVersion("linux-image-6.8.0-40-generic", "6.8.0-40.40", PMTypeAPT)
	if !ok || v != "6.8.0-40-generic" {
		t.Errorf("v = %q, ok = %v, want 6.8.0-40-generic, true (name suffix, not installed_version)", v, ok)
	}
}

func TestExtractKernelVersion_APT_NotAKernelPackage(t *testing.T) {
	if _, ok := ExtractKernelVersion("nginx", "1.26.0", PMTypeAPT); ok {
		t.Error("expected ok=false for a non-kernel package")
	}
}

func TestExtractKernelVersion_RPM(t *testing.T) {
	v, ok := ExtractKernelVersion("kernel-core", "5.14.0-427.31.1.el9_4", PMTypeDNF)
	if !ok || v != "5.14.0-427.31.1.el9_4" {
		t.Errorf("v = %q, ok = %v, want the installed_version verbatim", v, ok)
	}
}
