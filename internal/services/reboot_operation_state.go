package services

import "fmt"

// RebootStatus is the reboot_operations state machine (Step 11). Distinct
// from OperationStatus (Step 10's update-execution state machine) --
// reboots have phases (WAITING_FOR_VM/RECONNECTING) with no update
// equivalent, and TIMEOUT/UNKNOWN outcomes update operations never use.
type RebootStatus string

const (
	RebootPending      RebootStatus = "PENDING"
	RebootPrecheck     RebootStatus = "PRECHECK"
	RebootRebooting    RebootStatus = "REBOOTING"
	RebootWaitingForVM RebootStatus = "WAITING_FOR_VM"
	RebootReconnecting RebootStatus = "RECONNECTING"
	RebootVerifying    RebootStatus = "VERIFYING"
	RebootSuccess      RebootStatus = "SUCCESS"
	RebootPartial      RebootStatus = "PARTIAL"
	RebootFailed       RebootStatus = "FAILED"
	RebootTimeout      RebootStatus = "TIMEOUT"
	RebootUnknown      RebootStatus = "UNKNOWN"
	RebootCancelled    RebootStatus = "CANCELLED"
	RebootInterrupted  RebootStatus = "INTERRUPTED"
)

// terminalRebootStatuses never transition further -- to try again, an
// admin must request a brand new reboot operation (spec: "no automatic
// retry, ever" / "do not show [Reboot Again] automatically").
var terminalRebootStatuses = map[RebootStatus]bool{
	RebootSuccess: true, RebootPartial: true, RebootFailed: true, RebootTimeout: true,
	RebootUnknown: true, RebootCancelled: true, RebootInterrupted: true,
}

// validRebootTransitions: cancellation is only reachable from PENDING/
// PRECHECK (spec #51: "After REBOOT_SENT do not provide a cancel button
// -- the VM is already rebooting"). FAILED/TIMEOUT/UNKNOWN/INTERRUPTED
// are reachable from every non-terminal phase since a failure (SSH
// error, precheck failure, exhausted reconnect attempts) can happen at
// any point.
var validRebootTransitions = map[RebootStatus]map[RebootStatus]bool{
	RebootPending: {
		RebootPrecheck: true, RebootCancelled: true, RebootFailed: true, RebootInterrupted: true,
	},
	RebootPrecheck: {
		RebootRebooting: true, RebootCancelled: true, RebootFailed: true, RebootInterrupted: true,
	},
	RebootRebooting: {
		RebootWaitingForVM: true, RebootFailed: true, RebootInterrupted: true,
	},
	RebootWaitingForVM: {
		RebootReconnecting: true, RebootTimeout: true, RebootUnknown: true, RebootInterrupted: true,
	},
	RebootReconnecting: {
		RebootVerifying: true, RebootTimeout: true, RebootUnknown: true, RebootInterrupted: true,
	},
	RebootVerifying: {
		RebootSuccess: true, RebootPartial: true, RebootFailed: true, RebootUnknown: true, RebootInterrupted: true,
	},
}

// IsTerminalRebootStatus reports whether status is terminal.
func IsTerminalRebootStatus(status RebootStatus) bool {
	return terminalRebootStatuses[status]
}

// ErrInvalidRebootTransition is returned by ValidateRebootTransition for
// any edge not present in validRebootTransitions, including any
// transition out of a terminal status.
type ErrInvalidRebootTransition struct {
	From, To RebootStatus
}

func (e ErrInvalidRebootTransition) Error() string {
	return fmt.Sprintf("invalid reboot operation transition: %s -> %s", e.From, e.To)
}

// ValidateRebootTransition rejects any edge the state machine doesn't
// allow.
func ValidateRebootTransition(from, to RebootStatus) error {
	if terminalRebootStatuses[from] {
		return ErrInvalidRebootTransition{from, to}
	}
	if validRebootTransitions[from][to] {
		return nil
	}
	return ErrInvalidRebootTransition{from, to}
}
