package services

import "testing"

func TestValidateRebootTransition_HappyPath(t *testing.T) {
	steps := []RebootStatus{RebootPending, RebootPrecheck, RebootRebooting, RebootWaitingForVM, RebootReconnecting, RebootVerifying, RebootSuccess}
	for i := 0; i < len(steps)-1; i++ {
		if err := ValidateRebootTransition(steps[i], steps[i+1]); err != nil {
			t.Fatalf("expected %s -> %s valid, got %v", steps[i], steps[i+1], err)
		}
	}
}

func TestValidateRebootTransition_CancelOnlyBeforeRebootSent(t *testing.T) {
	if err := ValidateRebootTransition(RebootPending, RebootCancelled); err != nil {
		t.Errorf("PENDING -> CANCELLED should be valid: %v", err)
	}
	if err := ValidateRebootTransition(RebootPrecheck, RebootCancelled); err != nil {
		t.Errorf("PRECHECK -> CANCELLED should be valid: %v", err)
	}
	for _, from := range []RebootStatus{RebootRebooting, RebootWaitingForVM, RebootReconnecting, RebootVerifying} {
		if err := ValidateRebootTransition(from, RebootCancelled); err == nil {
			t.Errorf("%s -> CANCELLED must be rejected -- the VM is already rebooting", from)
		}
	}
}

func TestValidateRebootTransition_RejectsTerminalReentry(t *testing.T) {
	for _, from := range []RebootStatus{RebootSuccess, RebootFailed, RebootTimeout, RebootUnknown, RebootCancelled, RebootInterrupted} {
		if err := ValidateRebootTransition(from, RebootRebooting); err == nil {
			t.Errorf("expected %s -> REBOOTING to be rejected (terminal)", from)
		}
	}
}

func TestValidateRebootTransition_RejectsSkippingStates(t *testing.T) {
	if err := ValidateRebootTransition(RebootPending, RebootSuccess); err == nil {
		t.Error("expected PENDING -> SUCCESS to be rejected")
	}
	if err := ValidateRebootTransition(RebootPending, RebootRebooting); err == nil {
		t.Error("expected PENDING -> REBOOTING (skipping PRECHECK) to be rejected")
	}
}

func TestValidateRebootTransition_TimeoutAndUnknownReachableFromWaiting(t *testing.T) {
	for _, from := range []RebootStatus{RebootWaitingForVM, RebootReconnecting} {
		if err := ValidateRebootTransition(from, RebootTimeout); err != nil {
			t.Errorf("%s -> TIMEOUT should be valid: %v", from, err)
		}
		if err := ValidateRebootTransition(from, RebootUnknown); err != nil {
			t.Errorf("%s -> UNKNOWN should be valid: %v", from, err)
		}
	}
}

func TestIsTerminalRebootStatus(t *testing.T) {
	for _, s := range []RebootStatus{RebootSuccess, RebootFailed, RebootTimeout, RebootUnknown, RebootCancelled, RebootInterrupted} {
		if !IsTerminalRebootStatus(s) {
			t.Errorf("%s should be terminal", s)
		}
	}
	for _, s := range []RebootStatus{RebootPending, RebootPrecheck, RebootRebooting, RebootWaitingForVM, RebootReconnecting, RebootVerifying} {
		if IsTerminalRebootStatus(s) {
			t.Errorf("%s should NOT be terminal", s)
		}
	}
}
