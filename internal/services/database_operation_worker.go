package services

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
)

// DatabaseOperationWorker mirrors RebootExecutionWorker's exact shape: a
// bounded goroutine pool draining a buffered channel of operation IDs
// enqueued once DatabaseOperationService.Confirm's transactional claim
// succeeds. Per-database exclusivity needs no in-memory guard here
// either, for the same reason: the database-level claim (Confirm,
// checking GetActiveDatabaseOperationForDatabaseLocked) already
// guarantees at most one non-terminal operation per database.
//
// Its semaphore is sized by MAX_CONCURRENT_DATABASE_OPERATIONS -- a new,
// dedicated cap, entirely separate from MAX_CONCURRENT_VM_OPERATIONS/
// MAX_CONCURRENT_UPDATES, since this worker pool has nothing to do with
// either VM-side one.
type DatabaseOperationWorker struct {
	exec    *DatabaseOperationService
	workers int32
	sem     chan struct{}
	Jobs    chan uuid.UUID
	logger  *slog.Logger
}

// NewDatabaseOperationWorker creates a worker pool. workers is
// DATABASE_OPERATION_WORKERS; maxConcurrent is
// MAX_CONCURRENT_DATABASE_OPERATIONS.
func NewDatabaseOperationWorker(exec *DatabaseOperationService, workers, maxConcurrent int32, logger *slog.Logger) *DatabaseOperationWorker {
	if workers < 1 {
		workers = 1
	}
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DatabaseOperationWorker{
		exec: exec, workers: workers, sem: make(chan struct{}, maxConcurrent),
		Jobs: make(chan uuid.UUID, 64), logger: logger,
	}
}

// Enqueue hands operationID to the worker pool. Never blocks -- if the
// channel is somehow full, the operation stays PENDING and is picked up
// by the next startup's crash-recovery sweep.
func (w *DatabaseOperationWorker) Enqueue(operationID uuid.UUID) {
	select {
	case w.Jobs <- operationID:
	default:
		w.logger.Warn("database operation job queue full; operation will require manual recovery", "operation_id", operationID)
	}
}

// Run starts the fixed worker pool and blocks until ctx is cancelled.
func (w *DatabaseOperationWorker) Run(ctx context.Context) {
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

func (w *DatabaseOperationWorker) loop(ctx context.Context) {
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
