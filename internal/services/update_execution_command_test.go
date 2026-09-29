package services

import (
	"strings"
	"testing"
)

func TestBuildExecutionCommand_APT_SudoNoninteractive(t *testing.T) {
	cmd, ok := BuildExecutionCommand(APTCommandBuilder{}, []string{"nginx", "openssl"}, false, PrivilegeSudoNopasswd)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade nginx openssl -y"
	if cmd != want {
		t.Fatalf("got %q, want %q", cmd, want)
	}
}

func TestBuildExecutionCommand_DirectRoot_NoSudoPrefix(t *testing.T) {
	cmd, ok := BuildExecutionCommand(DNFCommandBuilder{}, []string{"curl"}, false, PrivilegeDirectRoot)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if strings.Contains(cmd, "sudo") {
		t.Fatalf("DIRECT_ROOT command must never contain sudo, got %q", cmd)
	}
	if cmd != "dnf upgrade curl -y" {
		t.Fatalf("got %q", cmd)
	}
}

func TestBuildExecutionCommand_Unsupported_Rejected(t *testing.T) {
	if _, ok := BuildExecutionCommand(YUMCommandBuilder{}, []string{"curl"}, false, PrivilegeUnsupported); ok {
		t.Fatal("UNSUPPORTED privilege must never produce an executable command")
	}
}

func TestBuildExecutionCommand_NoValidPackages_Rejected(t *testing.T) {
	if _, ok := BuildExecutionCommand(APTCommandBuilder{}, []string{}, false, PrivilegeSudoNopasswd); ok {
		t.Fatal("empty package list must never produce an executable command")
	}
}

func TestValidatePackageNamesForExecution_RejectsInjectionAttempts(t *testing.T) {
	malicious := []string{
		"nginx; rm -rf /",
		"nginx && whoami",
		"$(whoami)",
		"`whoami`",
		"nginx\nwhoami",
		"nginx|whoami",
		"nginx > /etc/passwd",
		"nginx < /etc/shadow",
		"nginx & whoami",
	}
	for _, name := range malicious {
		if err := ValidatePackageNamesForExecution([]string{name}); err == nil {
			t.Errorf("expected rejection for malicious package name %q, got nil error", name)
		}
	}
}

func TestValidatePackageNamesForExecution_AcceptsRealPackageNames(t *testing.T) {
	valid := []string{"nginx", "openssl", "linux-image-6.8.0-40-generic", "libc6:amd64", "python3.10"}
	if err := ValidatePackageNamesForExecution(valid); err != nil {
		t.Fatalf("unexpected rejection of valid package names: %v", err)
	}
}

func TestHashCommand_DeterministicAndDistinct(t *testing.T) {
	h1 := HashCommand("apt-get install --only-upgrade nginx -y")
	h2 := HashCommand("apt-get install --only-upgrade nginx -y")
	h3 := HashCommand("apt-get install --only-upgrade openssl -y")
	if h1 != h2 {
		t.Fatal("hash of the same command must be identical")
	}
	if h1 == h3 {
		t.Fatal("hash of different commands must differ")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64-char hex SHA-256 digest, got %d chars", len(h1))
	}
}
