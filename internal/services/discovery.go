package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// Fixed, backend-authored, read-only discovery commands (Step 5 §21).
// Never built from user input -- there is no command-injection surface
// here, and there must never be one: arbitrary command execution is
// explicitly out of scope for this step (§23/§24).
const (
	cmdOSRelease = "cat /etc/os-release"
	cmdKernel    = "uname -r"
	cmdArch      = "uname -m"
	cmdHostname  = "hostname"
	cmdCPU       = "nproc"
	cmdMemory    = "cat /proc/meminfo"
	cmdStorage   = "df -Pk /"
	cmdDocker    = "command -v docker"
)

// DiscoveryFieldResult is one command's outcome, for the "checklist" UI
// (Step 5 §57) -- rendered only from what the backend actually reports,
// never simulated client-side progress.
type DiscoveryFieldResult struct {
	Name      string
	Succeeded bool
	Error     string
}

// DiscoveryResult is a full discovery attempt's outcome.
type DiscoveryResult struct {
	Status            string // SUCCESS | PARTIAL | FAILED
	Hostname          *string
	OSName            *string
	OSVersion         *string
	DistributionID    *string
	KernelVersion     *string
	Architecture      *string
	CPUCores          *int32
	TotalMemoryBytes  *int64
	TotalStorageBytes *int64
	DockerInstalled   *bool
	Fields            []DiscoveryFieldResult
	ErrorSummary      string
}

// VMDiscoveryService orchestrates one discovery run: connect once via
// SSHService, run each fixed discovery command through RemoteExecutor,
// parse what came back, and persist only the fields that actually
// succeeded (Step 5 §35/§36 -- a failed field must never overwrite
// previously-known-good data, and one failed field must never fail the
// whole run).
type VMDiscoveryService struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	commandTimeout time.Duration
}

// NewVMDiscoveryService creates a VMDiscoveryService.
func NewVMDiscoveryService(store *repository.Store, ssh *SSHService, executor *RemoteExecutor, commandTimeout time.Duration) *VMDiscoveryService {
	return &VMDiscoveryService{store: store, ssh: ssh, executor: executor, commandTimeout: commandTimeout}
}

// Discover runs a full discovery attempt against resourceID. It always
// returns a DiscoveryResult (even on total failure) describing what
// happened; the returned error is non-nil only when discovery could not
// even be attempted (e.g. the VM record itself failed to load) or a
// database write failed -- a failed/partial SSH-level outcome is
// represented in DiscoveryResult.Status, not as a Go error, since it is
// an expected, handled outcome the caller must still be able to render.
func (s *VMDiscoveryService) Discover(ctx context.Context, resourceID uuid.UUID) (DiscoveryResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("load vm: %w", err)
	}

	run, err := s.store.CreateDiscoveryRun(ctx, vm.ID)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("create discovery run: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return DiscoveryResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		if _, err := s.store.CompleteDiscoveryRun(ctx, generated.CompleteDiscoveryRunParams{
			ID: run.ID, Status: "FAILED", ErrorSummary: pgutil.Text(sshErr.Message),
		}); err != nil {
			return DiscoveryResult{}, fmt.Errorf("complete discovery run: %w", err)
		}
		return DiscoveryResult{Status: "FAILED", ErrorSummary: "Connection failed: " + sshErr.Message}, nil
	}
	defer client.Close()

	result := DiscoveryResult{}
	var updateParams generated.UpdateVMDiscoveryResultParams
	updateParams.ID = vm.ID

	run1 := func(name, command string, apply func(stdout string) bool) {
		cmdResult, err := s.executor.Execute(ctx, client, command, s.commandTimeout)
		if err != nil {
			result.Fields = append(result.Fields, DiscoveryFieldResult{Name: name, Succeeded: false, Error: safeExecError(err)})
			return
		}
		if cmdResult.ExitCode != 0 {
			result.Fields = append(result.Fields, DiscoveryFieldResult{Name: name, Succeeded: false, Error: fmt.Sprintf("command exited with status %d", cmdResult.ExitCode)})
			return
		}
		ok := apply(cmdResult.Stdout)
		result.Fields = append(result.Fields, DiscoveryFieldResult{Name: name, Succeeded: ok})
	}

	run1("hostname", cmdHostname, func(out string) bool {
		h := strings.TrimSpace(out)
		if h == "" {
			return false
		}
		result.Hostname = &h
		updateParams.Hostname = pgutil.Text(h)
		return true
	})

	run1("os", cmdOSRelease, func(out string) bool {
		name, version, distID := parseOSRelease(out)
		if name == "" {
			return false
		}
		result.OSName = &name
		result.OSVersion = &version
		result.DistributionID = &distID
		updateParams.OsName = pgutil.Text(name)
		updateParams.OsVersion = pgutil.Text(version)
		updateParams.DistributionID = pgutil.Text(distID)
		return true
	})

	run1("kernel", cmdKernel, func(out string) bool {
		k := strings.TrimSpace(out)
		if k == "" {
			return false
		}
		result.KernelVersion = &k
		updateParams.KernelVersion = pgutil.Text(k)
		return true
	})

	run1("architecture", cmdArch, func(out string) bool {
		a := strings.TrimSpace(out)
		if a == "" {
			return false
		}
		result.Architecture = &a
		updateParams.Architecture = pgutil.Text(a)
		return true
	})

	run1("cpu", cmdCPU, func(out string) bool {
		cores, ok := parseCPUCores(out)
		if !ok {
			return false
		}
		result.CPUCores = &cores
		updateParams.CpuCores = pgutil.Int4(cores)
		return true
	})

	run1("memory", cmdMemory, func(out string) bool {
		bytes, ok := parseMemTotalBytes(out)
		if !ok {
			return false
		}
		result.TotalMemoryBytes = &bytes
		updateParams.TotalMemoryBytes = pgutil.Int8(bytes)
		return true
	})

	run1("storage", cmdStorage, func(out string) bool {
		bytes, ok := parseDFTotalBytes(out)
		if !ok {
			return false
		}
		result.TotalStorageBytes = &bytes
		updateParams.TotalStorageBytes = pgutil.Int8(bytes)
		return true
	})

	// Docker: a nonzero exit from `command -v docker` just means Docker
	// isn't installed -- that's valid, successfully-discovered data
	// (docker_installed=false), not a failure. Only an execution-level
	// error (timeout, session failure) counts as this field failing.
	dockerCmdResult, dockerErr := s.executor.Execute(ctx, client, cmdDocker, s.commandTimeout)
	if dockerErr != nil {
		result.Fields = append(result.Fields, DiscoveryFieldResult{Name: "docker", Succeeded: false, Error: safeExecError(dockerErr)})
	} else {
		installed := dockerCmdResult.ExitCode == 0
		result.DockerInstalled = &installed
		updateParams.DockerInstalled = pgutil.Bool(installed)
		result.Fields = append(result.Fields, DiscoveryFieldResult{Name: "docker", Succeeded: true})
	}

	succeeded, total := 0, len(result.Fields)
	var failedNames []string
	for _, f := range result.Fields {
		if f.Succeeded {
			succeeded++
		} else {
			failedNames = append(failedNames, f.Name)
		}
	}

	switch {
	case succeeded == total:
		result.Status = "SUCCESS"
	case succeeded == 0:
		result.Status = "FAILED"
		result.ErrorSummary = "Connection succeeded, but no information could be collected."
	default:
		result.Status = "PARTIAL"
		result.ErrorSummary = "Connection succeeded, but " + strings.Join(failedNames, ", ") + " could not be collected."
	}

	if _, err := s.store.UpdateVMDiscoveryResult(ctx, updateParams); err != nil {
		return DiscoveryResult{}, fmt.Errorf("save discovery result: %w", err)
	}
	if _, err := s.store.CompleteDiscoveryRun(ctx, generated.CompleteDiscoveryRunParams{
		ID: run.ID, Status: result.Status, ErrorSummary: pgutil.Text(result.ErrorSummary),
	}); err != nil {
		return DiscoveryResult{}, fmt.Errorf("complete discovery run: %w", err)
	}

	return result, nil
}

// safeExecError renders a RemoteExecutor error as a short, safe string --
// these only ever come from session/transport failures on fixed backend
// commands, never from anything containing credential material.
func safeExecError(err error) string {
	var sshErr *SSHError
	if errors.As(err, &sshErr) {
		return sshErr.Message
	}
	return "command execution failed"
}
