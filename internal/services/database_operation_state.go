package services

import "fmt"

// DatabaseOperationStatus is the database_operations state machine (Step
// 14): Recommendation -> Review -> Operation Plan -> Confirmation ->
// Execute -> Live Output -> Result -> Audit. Distinct from RebootStatus
// and OperationStatus (Step 10/11's own state machines) -- a database
// operation has no VM-reconnect phases and adds WAITING_CONFIRMATION,
// which neither of those needs (both already require confirmation inline
// on the request that creates them; this one is a genuinely separate
// step, per spec's dedicated POST .../operations/:id/confirm endpoint).
type DatabaseOperationStatus string

const (
	DBOpWaitingConfirmation DatabaseOperationStatus = "WAITING_CONFIRMATION"
	DBOpPending             DatabaseOperationStatus = "PENDING"
	DBOpRunning             DatabaseOperationStatus = "RUNNING"
	DBOpSuccess             DatabaseOperationStatus = "SUCCESS"
	DBOpFailed              DatabaseOperationStatus = "FAILED"
	DBOpCancelled           DatabaseOperationStatus = "CANCELLED"
	DBOpTimeout             DatabaseOperationStatus = "TIMEOUT"
)

// terminalDatabaseOperationStatuses never transition further -- to try
// again, an admin must request a brand new operation via Retry, which
// creates a new row referencing the failed one, never resurrects it
// (spec: "Do not automatically retry destructive operations").
var terminalDatabaseOperationStatuses = map[DatabaseOperationStatus]bool{
	DBOpSuccess: true, DBOpFailed: true, DBOpCancelled: true, DBOpTimeout: true,
}

// validDatabaseOperationTransitions: cancellation is only reachable from
// WAITING_CONFIRMATION/PENDING (spec's Lock/Query remediation section:
// "Never automatically kill sessions" -- once RUNNING has actually begun
// executing the backend-defined command, there is no safe way to abort
// mid-flight, mirroring RebootStatus's identical "cancel only before the
// command is sent" rule).
var validDatabaseOperationTransitions = map[DatabaseOperationStatus]map[DatabaseOperationStatus]bool{
	DBOpWaitingConfirmation: {
		DBOpPending: true, DBOpCancelled: true,
	},
	DBOpPending: {
		DBOpRunning: true, DBOpCancelled: true, DBOpFailed: true,
	},
	DBOpRunning: {
		DBOpSuccess: true, DBOpFailed: true, DBOpTimeout: true,
	},
}

// IsTerminalDatabaseOperationStatus reports whether status is terminal.
func IsTerminalDatabaseOperationStatus(status DatabaseOperationStatus) bool {
	return terminalDatabaseOperationStatuses[status]
}

// ErrInvalidDatabaseOperationTransition is returned by
// ValidateDatabaseOperationTransition for any edge not present in
// validDatabaseOperationTransitions, including any transition out of a
// terminal status.
type ErrInvalidDatabaseOperationTransition struct {
	From, To DatabaseOperationStatus
}

func (e ErrInvalidDatabaseOperationTransition) Error() string {
	return fmt.Sprintf("invalid database operation transition: %s -> %s", e.From, e.To)
}

// ValidateDatabaseOperationTransition rejects any edge the state machine
// doesn't allow.
func ValidateDatabaseOperationTransition(from, to DatabaseOperationStatus) error {
	if terminalDatabaseOperationStatuses[from] {
		return ErrInvalidDatabaseOperationTransition{from, to}
	}
	if validDatabaseOperationTransitions[from][to] {
		return nil
	}
	return ErrInvalidDatabaseOperationTransition{from, to}
}
