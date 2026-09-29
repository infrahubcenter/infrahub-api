package services

import "testing"

func TestBuildRebootCommand_SystemctlPreferred(t *testing.T) {
	cmd, ok := BuildRebootCommand(true, PrivilegeDirectRoot)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cmd != "systemctl reboot" {
		t.Fatalf("got %q, want %q", cmd, "systemctl reboot")
	}
}

func TestBuildRebootCommand_FallsBackWithoutSystemctl(t *testing.T) {
	cmd, ok := BuildRebootCommand(false, PrivilegeDirectRoot)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cmd != "reboot" {
		t.Fatalf("got %q, want %q", cmd, "reboot")
	}
}

func TestBuildRebootCommand_SudoPrefixForNonRoot(t *testing.T) {
	cmd, ok := BuildRebootCommand(true, PrivilegeSudoNopasswd)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cmd != "sudo -n systemctl reboot" {
		t.Fatalf("got %q, want %q", cmd, "sudo -n systemctl reboot")
	}
}

func TestBuildRebootCommand_UnsupportedPrivilege_Rejected(t *testing.T) {
	if _, ok := BuildRebootCommand(true, PrivilegeUnsupported); ok {
		t.Fatal("UNSUPPORTED privilege must never produce an executable reboot command")
	}
}

func TestBuildRebootCommand_NeverAcceptsInput(t *testing.T) {
	// BuildRebootCommand's signature itself is the safety property under
	// test: it takes only a bool and a PrivilegeMode -- there is no
	// string/command parameter anywhere for a caller to inject through.
	// This test exists so a future signature change (e.g. adding a
	// "extra args" string parameter) fails a code review expectation, not
	// silently reintroduces an injection surface.
	cmd, ok := BuildRebootCommand(true, PrivilegeDirectRoot)
	if !ok || cmd == "" {
		t.Fatal("sanity check failed")
	}
}
