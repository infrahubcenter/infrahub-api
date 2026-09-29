package services

import (
	"context"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// PrivilegeMode is the detected (never admin-typed) capability of the
// configured SSH user to run privileged package-management commands.
// Re-detected fresh at every precheck/revalidation and never trusted
// stale for an actual execution decision -- see vms.privilege_mode's
// migration comment.
type PrivilegeMode string

const (
	PrivilegeDirectRoot   PrivilegeMode = "DIRECT_ROOT"
	PrivilegeSudoNopasswd PrivilegeMode = "SUDO_NOPASSWD"
	PrivilegeUnsupported  PrivilegeMode = "UNSUPPORTED"
)

const (
	cmdWhoAmI      = "whoami"
	cmdSudoNonIntv = "sudo -n true"
)

// DetectPrivilegeMode determines whether the configured SSH user can run
// package-management commands, using only real evidence from the VM:
//   - whoami == "root"            -> DIRECT_ROOT, no sudo needed at all.
//   - `sudo -n true` exits 0      -> SUDO_NOPASSWD (non-interactive sudo works).
//   - anything else               -> UNSUPPORTED (would require an interactive
//     sudo password prompt, which this project never supplies -- spec:
//     "no interactive sudo password prompting").
func DetectPrivilegeMode(ctx context.Context, client *ssh.Client, executor *RemoteExecutor, commandTimeout time.Duration) (PrivilegeMode, error) {
	whoRes, err := executor.Execute(ctx, client, cmdWhoAmI, commandTimeout)
	if err != nil {
		return PrivilegeUnsupported, err
	}
	if strings.TrimSpace(whoRes.Stdout) == "root" {
		return PrivilegeDirectRoot, nil
	}

	sudoRes, err := executor.Execute(ctx, client, cmdSudoNonIntv, commandTimeout)
	if err != nil {
		return PrivilegeUnsupported, err
	}
	if sudoRes.ExitCode == 0 {
		return PrivilegeSudoNopasswd, nil
	}
	return PrivilegeUnsupported, nil
}
