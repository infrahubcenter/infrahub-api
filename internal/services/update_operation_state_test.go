package services

import "testing"

func TestValidateOperationTransition_HappyPath(t *testing.T) {
	steps := []OperationStatus{OpPending, OpConnecting, OpRunning, OpVerifying, OpSuccess}
	for i := 0; i < len(steps)-1; i++ {
		if err := ValidateOperationTransition(steps[i], steps[i+1]); err != nil {
			t.Fatalf("expected %s -> %s to be valid, got %v", steps[i], steps[i+1], err)
		}
	}
}

func TestValidateOperationTransition_RejectsTerminalReentry(t *testing.T) {
	cases := []struct{ from, to OperationStatus }{
		{OpSuccess, OpRunning},
		{OpFailed, OpRunning},
		{OpCancelled, OpConnecting},
		{OpPartial, OpVerifying},
		{OpInterrupted, OpRunning},
	}
	for _, c := range cases {
		if err := ValidateOperationTransition(c.from, c.to); err == nil {
			t.Errorf("expected %s -> %s to be rejected (terminal state), got nil", c.from, c.to)
		}
	}
}

func TestValidateOperationTransition_RejectsSkippingStates(t *testing.T) {
	if err := ValidateOperationTransition(OpPending, OpSuccess); err == nil {
		t.Error("expected PENDING -> SUCCESS to be rejected")
	}
	if err := ValidateOperationTransition(OpPending, OpRunning); err == nil {
		t.Error("expected PENDING -> RUNNING (skipping CONNECTING) to be rejected")
	}
}

func TestValidateOperationTransition_CancelOnlyBeforeRunning(t *testing.T) {
	if err := ValidateOperationTransition(OpPending, OpCancelled); err != nil {
		t.Errorf("PENDING -> CANCELLED should be valid: %v", err)
	}
	if err := ValidateOperationTransition(OpConnecting, OpCancelled); err != nil {
		t.Errorf("CONNECTING -> CANCELLED should be valid: %v", err)
	}
	if err := ValidateOperationTransition(OpRunning, OpCancelled); err == nil {
		t.Error("RUNNING -> CANCELLED must be rejected -- cancellation is unavailable once package changes are in progress")
	}
	if err := ValidateOperationTransition(OpVerifying, OpCancelled); err == nil {
		t.Error("VERIFYING -> CANCELLED must be rejected")
	}
}

func TestValidateOperationTransition_FailedReachableFromAnyNonTerminal(t *testing.T) {
	for _, from := range []OperationStatus{OpPending, OpConnecting, OpRunning, OpVerifying} {
		if err := ValidateOperationTransition(from, OpFailed); err != nil {
			t.Errorf("%s -> FAILED should always be valid: %v", from, err)
		}
		if err := ValidateOperationTransition(from, OpInterrupted); err != nil {
			t.Errorf("%s -> INTERRUPTED should always be valid: %v", from, err)
		}
	}
}

func TestPlanStatusForOperation(t *testing.T) {
	cases := map[OperationStatus]string{
		OpSuccess:     "COMPLETED",
		OpPartial:     "PARTIAL",
		OpFailed:      "FAILED",
		OpCancelled:   "FAILED",
		OpInterrupted: "FAILED",
	}
	for status, want := range cases {
		if got := planStatusForOperation(status); got != want {
			t.Errorf("planStatusForOperation(%s) = %s, want %s", status, got, want)
		}
	}
}
