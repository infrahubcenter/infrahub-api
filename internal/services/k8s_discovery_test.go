package services

import "testing"

// Kubernetes reports pod phase as corev1.PodPhase's exact capitalized-
// first-letter-only strings ("Running", "Pending", ...) -- the agent
// forwards that verbatim. k8s_pods.phase's CHECK constraint only accepts
// the all-caps form. Without normalizeK8sPodPhase, every UpsertK8sPod
// call fails its CHECK constraint on the very first pod of every scan,
// so discovery silently never records a single pod even though the
// agent's own ListPods call already succeeded -- the root cause of a
// live, connected cluster always showing "Pods: 0".
func TestNormalizeK8sPodPhase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Running", "RUNNING"},
		{"Pending", "PENDING"},
		{"Succeeded", "SUCCEEDED"},
		{"Failed", "FAILED"},
		{"Unknown", "UNKNOWN"},
		{"RUNNING", "RUNNING"}, // already-uppercase input must still pass through
		{"", "UNKNOWN"},        // never let an INSERT fail outright over an unrecognized value
		{"CrashLoopBackOff", "UNKNOWN"},
	}
	for _, c := range cases {
		if got := normalizeK8sPodPhase(c.in); got != c.want {
			t.Errorf("normalizeK8sPodPhase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
