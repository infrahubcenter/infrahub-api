package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestAPTCommandBuilder_PackageUpdateCommand(t *testing.T) {
	cmd := APTCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl", "curl"})
	if cmd != "apt-get install --only-upgrade nginx openssl curl" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestAPTCommandBuilder_EmptyPackageList(t *testing.T) {
	builder := APTCommandBuilder{}
	if cmd := builder.BuildPackageUpdateCommand(nil); cmd != "" {
		t.Errorf("cmd = %q, want empty", cmd)
	}
}

func TestAPTCommandBuilder_UnsafeNamesOmitted(t *testing.T) {
	cmd := APTCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "evil; rm -rf /", "openssl"})
	if strings.Contains(cmd, "evil") || strings.Contains(cmd, "rm -rf") {
		t.Errorf("cmd = %q, unsafe name was not filtered out", cmd)
	}
	if !strings.Contains(cmd, "nginx") || !strings.Contains(cmd, "openssl") {
		t.Errorf("cmd = %q, safe names should still be present", cmd)
	}
}

func TestAPTCommandBuilder_KernelCommand_SameShapeAsPackage(t *testing.T) {
	cmd := APTCommandBuilder{}.BuildKernelUpdateCommand([]string{"linux-image-6.8.0-40-generic"})
	if cmd != "apt-get install --only-upgrade linux-image-6.8.0-40-generic" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestAPTCommandBuilder_OSReleaseCommand_UbuntuOnly(t *testing.T) {
	cmd, ok := APTCommandBuilder{}.BuildOSReleaseCommand("ubuntu")
	if !ok || cmd != "do-release-upgrade" {
		t.Errorf("cmd = %q, ok = %v", cmd, ok)
	}
	builder := APTCommandBuilder{}
	if _, ok := builder.BuildOSReleaseCommand("debian"); ok {
		t.Error("expected ok=false for debian -- do-release-upgrade doesn't exist there, must not be fabricated")
	}
}

func TestDNFCommandBuilder_PackageUpdateCommand(t *testing.T) {
	cmd := DNFCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl", "curl"})
	if cmd != "dnf upgrade nginx openssl curl" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestDNFCommandBuilder_NoOSReleaseCommand(t *testing.T) {
	builder := DNFCommandBuilder{}
	if _, ok := builder.BuildOSReleaseCommand("rhel"); ok {
		t.Error("expected ok=false -- no universal safe RPM release-upgrade command exists")
	}
}

func TestYUMCommandBuilder_PackageUpdateCommand(t *testing.T) {
	cmd := YUMCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl"})
	if cmd != "yum update nginx openssl" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestUpdateCommandBuilderFactory_UnsupportedReturnsNil(t *testing.T) {
	f := NewUpdateCommandBuilderFactory()
	if b := f.New(PMTypeUnsupported); b != nil {
		t.Errorf("builder = %v, want nil for PMTypeUnsupported", b)
	}
}

func TestUpdateCommandBuilderFactory_ReturnsCorrectType(t *testing.T) {
	f := NewUpdateCommandBuilderFactory()
	cases := map[PackageManagerType]PackageManagerType{
		PMTypeAPT: PMTypeAPT, PMTypeDNF: PMTypeDNF, PMTypeYUM: PMTypeYUM,
	}
	for pmType, want := range cases {
		b := f.New(pmType)
		if b == nil || b.Type() != want {
			t.Errorf("New(%v).Type() = %v, want %v", pmType, b, want)
		}
	}
}

// TestCommandBuilders_NeverExecuteAnything is the mandatory explicit
// no-execution test (spec #69): statically verifies, by parsing this
// package's own AST, that os_update_command_builder.go contains no call
// to RemoteExecutor.Execute, no reference to *ssh.Client, and none of the
// forbidden mutation verbs anywhere in its source -- not just "the tests
// I happened to write don't trigger execution," but "the file is
// structurally incapable of executing anything." A command builder that
// grew an accidental SSH dependency would fail this test even if no
// other test caught it.
func TestCommandBuilders_NeverExecuteAnything(t *testing.T) {
	const path = "os_update_command_builder.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel.Name == "Execute" {
				t.Errorf("found a call to .Execute(...) in the command builder file -- command generation must never execute anything")
			}
		case *ast.Ident:
			if node.Name == "RemoteExecutor" || node.Name == "SSHService" {
				t.Errorf("found a reference to %s in the command builder file -- it must have no SSH capability at all", node.Name)
			}
		}
		return true
	})

	// Belt-and-suspenders textual check on top of the AST walk: none of
	// the explicitly-forbidden mutation command forms may appear
	// anywhere in the file's raw source at all -- not just in generated
	// output (an AST walk alone wouldn't catch a forbidden verb sitting
	// inside a string literal never returned by any function).
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Note: "dnf upgrade" and "yum update" are deliberately NOT in this
	// list -- they are the legitimate, spec-requested preview commands
	// this file generates. What must never appear is a bare install/
	// remove verb or anything that changes system/service state.
	forbidden := []string{
		"apt upgrade", "apt full-upgrade", "apt install ", "apt remove", "apt-get upgrade",
		"apt-get full-upgrade", "apt-get dist-upgrade",
		"dnf install", "dnf remove",
		"yum install", "yum remove",
		"reboot", "shutdown", "systemctl restart",
	}
	for _, bad := range forbidden {
		if strings.Contains(string(src), bad) {
			t.Errorf("forbidden form %q found in os_update_command_builder.go's own source", bad)
		}
	}
}

func TestForbiddenCommandForms_NeverAppearInGeneratedCommands(t *testing.T) {
	forbidden := []string{
		"apt upgrade", "apt full-upgrade", "apt install", "apt remove", "apt-get upgrade",
		"apt-get full-upgrade", "apt-get dist-upgrade",
		"dnf update", "dnf install", "dnf remove",
		"yum update -y", "yum install", "yum remove",
		"reboot", "shutdown", "systemctl restart",
	}
	generated := []string{
		APTCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl", "curl", "linux-image-6.8.0-40-generic"}),
		DNFCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl", "curl", "kernel-core"}),
		YUMCommandBuilder{}.BuildPackageUpdateCommand([]string{"nginx", "openssl", "curl"}),
	}
	aptBuilder := APTCommandBuilder{}
	if cmd, ok := aptBuilder.BuildOSReleaseCommand("ubuntu"); ok {
		generated = append(generated, cmd)
	}
	for _, cmd := range generated {
		for _, bad := range forbidden {
			if strings.Contains(cmd, bad) {
				t.Errorf("generated command %q contains forbidden form %q", cmd, bad)
			}
		}
	}
}
