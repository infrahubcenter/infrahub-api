package services

import "fmt"

// OperationStatus is the execution-engine state machine for one operations
// row (operation_type IN ('OS_UPDATE','PACKAGE_UPDATE')). Distinct from
// update_plans.status -- an operation tracks one execution attempt, a plan
// tracks the reviewable, admin-approved selection that attempt came from.
type OperationStatus string

const (
	OpPending     OperationStatus = "PENDING"
	OpConnecting  OperationStatus = "CONNECTING"
	OpRunning     OperationStatus = "RUNNING"
	OpVerifying   OperationStatus = "VERIFYING"
	OpSuccess     OperationStatus = "SUCCESS"
	OpFailed      OperationStatus = "FAILED"
	OpPartial     OperationStatus = "PARTIAL"
	OpCancelled   OperationStatus = "CANCELLED"
	OpInterrupted OperationStatus = "INTERRUPTED"
)

// terminalOperationStatuses never transition further. To retry a failed/
// partial/interrupted operation, an admin must create (and revalidate) a
// new plan and a new operation -- this project never mutates completed
// operation history or auto-retries (spec, repeated emphasis).
var terminalOperationStatuses = map[OperationStatus]bool{
	OpSuccess: true, OpFailed: true, OpPartial: true, OpCancelled: true, OpInterrupted: true,
}

// validOperationTransitions enumerates every allowed edge in the state
// machine. FAILED and INTERRUPTED are reachable from every non-terminal
// state (a failure/crash can happen at any point); CANCELLED is only
// reachable from PENDING/CONNECTING (spec: "cancellation is unavailable
// once package changes are in progress" -- RUNNING/VERIFYING can never be
// cancelled).
var validOperationTransitions = map[OperationStatus]map[OperationStatus]bool{
	OpPending: {
		OpConnecting: true, OpCancelled: true, OpFailed: true, OpInterrupted: true,
	},
	OpConnecting: {
		OpRunning: true, OpCancelled: true, OpFailed: true, OpInterrupted: true,
	},
	OpRunning: {
		OpVerifying: true, OpFailed: true, OpInterrupted: true,
	},
	OpVerifying: {
		OpSuccess: true, OpPartial: true, OpFailed: true, OpInterrupted: true,
	},
}

// ErrInvalidOperationTransition is returned by ValidateOperationTransition
// for any edge not present in validOperationTransitions, including any
// transition out of a terminal status.
type ErrInvalidOperationTransition struct {
	From, To OperationStatus
}

func (e ErrInvalidOperationTransition) Error() string {
	return fmt.Sprintf("invalid update operation transition: %s -> %s", e.From, e.To)
}

// IsTerminalOperationStatus reports whether status is terminal (no further
// transitions ever allowed) -- exported for callers outside this package,
// e.g. the log-stream handler deciding when to stop polling.
func IsTerminalOperationStatus(status OperationStatus) bool {
	return terminalOperationStatuses[status]
}

// ValidateOperationTransition rejects any edge the state machine doesn't
// allow -- e.g. SUCCESS -> RUNNING, FAILED -> RUNNING, or skipping straight
// from PENDING to SUCCESS.
func ValidateOperationTransition(from, to OperationStatus) error {
	if terminalOperationStatuses[from] {
		return ErrInvalidOperationTransition{from, to}
	}
	if validOperationTransitions[from][to] {
		return nil
	}
	return ErrInvalidOperationTransition{from, to}
}
