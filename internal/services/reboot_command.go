package services

// This file generates the reboot command string only -- structurally like
// os_update_command_builder.go (Step 9)/update_execution_command.go (Step
// 10): a pure function from already-detected facts (privilege mode,
// whether systemctl exists) to a fixed command string, never from
// anything a client submits. There is no {"command": "..."} field
// anywhere in this project's reboot request shape (spec: "Do not accept
// arbitrary command from frontend") -- the two possible base commands
// below are the only strings this file can ever produce.
const (
	cmdSystemctlReboot = "systemctl reboot"
	cmdBareReboot      = "reboot"
	cmdHasSystemctl    = "command -v systemctl"
)

// BuildRebootCommand renders the exact reboot command to execute:
// `systemctl reboot` when the VM has systemd (the controlled, preferred
// mechanism -- spec's explicit preference), falling back to the bare
// `reboot` command otherwise, with a privilege prefix applied exactly
// like BuildExecutionCommand (Step 10): bare for DIRECT_ROOT, `sudo -n `
// for SUDO_NOPASSWD, rejected for UNSUPPORTED (never an interactive sudo
// password prompt).
func BuildRebootCommand(hasSystemctl bool, privilege PrivilegeMode) (command string, ok bool) {
	base := cmdBareReboot
	if hasSystemctl {
		base = cmdSystemctlReboot
	}
	switch privilege {
	case PrivilegeDirectRoot:
		return base, true
	case PrivilegeSudoNopasswd:
		return "sudo -n " + base, true
	default:
		return "", false
	}
}
