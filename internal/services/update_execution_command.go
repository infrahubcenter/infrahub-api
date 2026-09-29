package services

import "strings"

// This file builds the *actual executable* command (Step 10), layered
// additively on top of os_update_command_builder.go's preview strings
// (Step 9) rather than modifying them -- GetPlan's existing preview
// rendering and its tests keep asserting the exact bare command; this is
// a separate, explicit step that only the execution engine calls.
//
// Two things are added that a preview doesn't need: (1) non-interactive
// flags, so the command never hangs waiting on a stdin that RemoteExecutor
// never supplies (spec: "package operations must not hang waiting for
// input"), and (2) a privilege prefix resolved from a freshly-detected
// PrivilegeMode, never from a client-supplied flag.

// BuildExecutionCommand turns a preview-shaped command builder call into
// the exact string that will be sent over the SSH exec channel: the base
// package-manager command (via builder, which already whitelist-filters
// package names -- see safePackageNamePattern), non-interactive flags
// appended, and a privilege prefix applied. ok is false when privilege is
// PrivilegeUnsupported (no safe way to run a privileged command) or when
// the builder produced no command at all (no valid package names).
func BuildExecutionCommand(builder UpdateCommandBuilder, packageNames []string, isKernel bool, privilege PrivilegeMode) (command string, ok bool) {
	var base string
	if isKernel {
		base = builder.BuildKernelUpdateCommand(packageNames)
	} else {
		base = builder.BuildPackageUpdateCommand(packageNames)
	}
	if base == "" {
		return "", false
	}

	switch builder.Type() {
	case PMTypeAPT:
		// -y: assume yes to confirmation prompts. DEBIAN_FRONTEND via the
		// standalone `env` utility (not sudo's own env-passthrough, which
		// depends on sudoers env_keep and can silently fail to propagate)
		// suppresses debconf UI prompts from package postinst scripts.
		base = "env DEBIAN_FRONTEND=noninteractive " + base + " -y"
	case PMTypeDNF, PMTypeYUM:
		base += " -y"
	default:
		return "", false
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

// EstimatedExecutionCommand renders the command a plan would run assuming
// SUDO_NOPASSWD (the common case for a non-root SSH user) purely for
// display in the plan/confirmation UI before real precheck-time privilege
// detection has run -- clearly an estimate, never what's actually
// executed. sshUsername "root" is shown without a sudo prefix since that
// case is cheaply knowable without any SSH round trip.
func EstimatedExecutionCommand(builder UpdateCommandBuilder, packageNames []string, isKernel bool, sshUsername string) (string, bool) {
	privilege := PrivilegeSudoNopasswd
	if strings.EqualFold(sshUsername, "root") {
		privilege = PrivilegeDirectRoot
	}
	return BuildExecutionCommand(builder, packageNames, isKernel, privilege)
}
