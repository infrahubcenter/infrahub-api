package services

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
)

// UpdateExecutionWorker is a bounded-concurrency consumer of operation IDs
// created by UpdateExecutionService.RequestExecution -- mirrors the fixed
// worker-pool-draining-a-buffered-channel shape established by
// PackageScanScheduler/DockerDiscoveryScheduler (Steps 6-8), but reacts to
// HTTP-created jobs pushed onto Jobs rather than a ticker.
//
// Two independent concurrency limits, both spec-named: UPDATE_WORKERS
// (goroutine pool size -- how many operations can be *dequeued* at once)
// and MAX_CONCURRENT_UPDATES (a semaphore gating how many can actually be
// *connected to a VM and running* at once, which may be smaller). Per-VM
// exclusivity itself needs no in-memory guard here: the database-level
// transactional claim in RequestExecution already guarantees at most one
// non-terminal operation per VM exists, so the worker pool can never be
// handed two jobs for the same VM concurrently.
type UpdateExecutionWorker struct {
	exec    *UpdateExecutionService
	workers int32
	sem     chan struct{}
	Jobs    chan uuid.UUID
	logger  *slog.Logger
}

// NewUpdateExecutionWorker creates a worker pool. workers is UPDATE_WORKERS
// (goroutine count); maxConcurrent is MAX_CONCURRENT_UPDATES (the
// semaphore); Jobs is buffered generously so RequestExecution's Enqueue
// never blocks the HTTP request that created the operation.
func NewUpdateExecutionWorker(exec *UpdateExecutionService, workers, maxConcurrent int32, logger *slog.Logger) *UpdateExecutionWorker {
	if workers < 1 {
		workers = 1
	}
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &UpdateExecutionWorker{
		exec: exec, workers: workers, sem: make(chan struct{}, maxConcurrent),
		Jobs: make(chan uuid.UUID, 64), logger: logger,
	}
}

// Enqueue hands operationID to the worker pool. Never blocks (Jobs is
// generously buffered) -- if the channel is somehow full, the operation
// simply stays PENDING in the database and is picked up as INTERRUPTED by
// the next startup's crash-recovery sweep rather than silently lost.
func (w *UpdateExecutionWorker) Enqueue(operationID uuid.UUID) {
	select {
	case w.Jobs <- operationID:
	default:
		w.logger.Warn("update execution job queue full; operation will require manual recovery", "operation_id", operationID)
	}
}

// Run starts the fixed worker pool and blocks until ctx is cancelled,
// matching every other scheduler's Run(ctx) shape in this project.
func (w *UpdateExecutionWorker) Run(ctx context.Context) {
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

func (w *UpdateExecutionWorker) loop(ctx context.Context) {
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
