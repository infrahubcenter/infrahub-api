package services

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
)

// RebootExecutionWorker mirrors UpdateExecutionWorker's exact shape: a
// bounded goroutine pool draining a buffered channel of operation IDs
// created by RebootExecutionService.RequestReboot's transactional claim.
// Per-VM exclusivity needs no in-memory guard here either, for the same
// reason: the database-level claim (RequestReboot, checking both
// GetActiveOperationForResourceLocked and GetActiveRebootForResourceLocked)
// already guarantees at most one non-terminal reboot per VM, and that a
// VM with an active reboot can never also claim an update operation (and
// vice versa).
//
// Its semaphore is sized by MAX_CONCURRENT_VM_OPERATIONS -- a new,
// deliberately separate cap from MAX_CONCURRENT_UPDATES (Step 10's own,
// unchanged), per spec's "prefer a general operation cap, don't
// over-engineer": rather than retrofitting Step 10's already-tested
// worker with a shared semaphore, this step gets its own, sized by a
// config name that reads as the general one future operation types
// (Docker, OS upgrade) would also adopt.
type RebootExecutionWorker struct {
	exec    *RebootExecutionService
	workers int32
	sem     chan struct{}
	Jobs    chan uuid.UUID
	logger  *slog.Logger
}

// NewRebootExecutionWorker creates a worker pool. workers is
// REBOOT_WORKERS; maxConcurrent is MAX_CONCURRENT_VM_OPERATIONS.
func NewRebootExecutionWorker(exec *RebootExecutionService, workers, maxConcurrent int32, logger *slog.Logger) *RebootExecutionWorker {
	if workers < 1 {
		workers = 1
	}
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RebootExecutionWorker{
		exec: exec, workers: workers, sem: make(chan struct{}, maxConcurrent),
		Jobs: make(chan uuid.UUID, 64), logger: logger,
	}
}

// Enqueue hands operationID to the worker pool. Never blocks -- if the
// channel is somehow full, the operation stays PENDING and is picked up
// as INTERRUPTED by the next startup's crash-recovery sweep.
func (w *RebootExecutionWorker) Enqueue(operationID uuid.UUID) {
	select {
	case w.Jobs <- operationID:
	default:
		w.logger.Warn("reboot execution job queue full; operation will require manual recovery", "operation_id", operationID)
	}
}

// Run starts the fixed worker pool and blocks until ctx is cancelled.
func (w *RebootExecutionWorker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(int(w.workers))
	for i := int32(0); i < w.workers; i++ {
		go func() {
			defer wg.Done()
			w.loop(ctx)
		}()
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *RebootExecutionWorker) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case operationID := <-w.Jobs:
			select {
			case w.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			w.exec.Run(ctx, operationID)
			<-w.sem
		}
	}
}
