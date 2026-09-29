package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CommandResult is one remote command's outcome. Stdout/Stderr are plain
// text -- the discovery commands this step runs are all fixed, read-only,
// backend-authored strings (Step 5 §21-24), never anything derived from
// user input, so there is no command-injection surface here.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// RemoteExecutor runs a single command per SSH session (x/crypto/ssh
// sessions are one-shot: at most one Run/Shell/Subsystem call each) and
// enforces ctx cancellation by closing the session if ctx is done before
// the command finishes -- x/crypto/ssh has no native context support.
type RemoteExecutor struct{}

// NewRemoteExecutor creates a RemoteExecutor.
func NewRemoteExecutor() *RemoteExecutor {
	return &RemoteExecutor{}
}

// Execute runs command on client and waits for it to finish, ctx
// cancellation, or timeout, whichever comes first. It always closes the
// session before returning.
func (RemoteExecutor) Execute(ctx context.Context, client *ssh.Client, command string, timeout time.Duration) (CommandResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return CommandResult{}, fmt.Errorf("open session: %w", err)
	}
	defer session.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-runCtx.Done():
		_ = session.Close() // aborts the in-flight command; Run's goroutine then exits with a session-closed error, which we discard
		return CommandResult{}, newSSHError(ErrCodeTimeout, "Command timed out.", runCtx.Err())
	case runErr := <-done:
		result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
		var exitErr *ssh.ExitError
		switch {
		case runErr == nil:
			result.ExitCode = 0
		case errors.As(runErr, &exitErr):
			result.ExitCode = exitErr.ExitStatus()
		default:
			// Session/transport-level failure (not a nonzero exit) --
			// still return what we captured, exit code -1 signals "did
			// not complete normally" to callers.
			result.ExitCode = -1
			return result, fmt.Errorf("run command: %w", runErr)
		}
		return result, nil
	}
}

// ExecuteWithStdin runs command exactly like Execute, but feeds stdin to
// the remote process's standard input first -- used by the Docker agent
// installer to push a file's bytes over an SSH exec channel via `sudo -n
// tee <path> > /dev/null` without needing a separate SFTP dependency.
func (RemoteExecutor) ExecuteWithStdin(ctx context.Context, client *ssh.Client, command string, timeout time.Duration, stdin []byte) (CommandResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return CommandResult{}, fmt.Errorf("open session: %w", err)
	}
	defer session.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	session.Stdin = bytes.NewReader(stdin)
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-runCtx.Done():
		_ = session.Close()
		return CommandResult{}, newSSHError(ErrCodeTimeout, "Command timed out.", runCtx.Err())
	case runErr := <-done:
		result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
		var exitErr *ssh.ExitError
		switch {
		case runErr == nil:
			result.ExitCode = 0
		case errors.As(runErr, &exitErr):
			result.ExitCode = exitErr.ExitStatus()
		default:
			result.ExitCode = -1
			return result, fmt.Errorf("run command: %w", runErr)
		}
		return result, nil
	}
}

// OutputChunk is one incremental slice of output from a streaming command
// execution, delivered as it arrives rather than buffered to the end.
type OutputChunk struct {
	Stream string // "STDOUT" or "STDERR"
	Data   string
}

// lineWriter is an io.Writer that splits arbitrary Write() calls on '\n'
// and calls onLine once per complete line, buffering any trailing partial
// line until the next Write or Close. This turns SSH's raw byte stream
// (which can split output at any byte boundary) into the line-oriented
// chunks operation_logs / the WebSocket log stream expect.
type lineWriter struct {
	stream string
	onLine func(stream, line string)
	buf    bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		b := w.buf.Bytes()
		idx := bytes.IndexByte(b, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(b[:idx]), "\r")
		w.buf.Next(idx + 1)
		w.onLine(w.stream, line)
	}
	return len(p), nil
}

// flush emits any remaining partial line (a command whose final line
// isn't newline-terminated must not silently lose that output).
func (w *lineWriter) flush() {
	if w.buf.Len() > 0 {
		w.onLine(w.stream, strings.TrimRight(w.buf.String(), "\r"))
		w.buf.Reset()
	}
}

// ExecuteStreaming runs command exactly like Execute, but invokes onLine
// once per complete output line as it arrives (from either stream) instead
// of only returning the full buffered output at the end. Used solely by
// the update execution engine (Step 10) for live log streaming -- every
// other caller (discovery, monitoring, package/docker scans) uses the
// fixed, fast, buffered Execute above and has no reason to change.
func (RemoteExecutor) ExecuteStreaming(ctx context.Context, client *ssh.Client, command string, timeout time.Duration, onLine func(stream, line string)) (CommandResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return CommandResult{}, fmt.Errorf("open session: %w", err)
	}
	defer session.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var full bytes.Buffer
	stdoutW := &lineWriter{stream: "STDOUT", onLine: onLine}
	stderrW := &lineWriter{stream: "STDERR", onLine: onLine}
	session.Stdout = io.MultiWriter(stdoutW, &full)
	session.Stderr = stderrW

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-runCtx.Done():
		_ = session.Close()
		stdoutW.flush()
		stderrW.flush()
		return CommandResult{}, newSSHError(ErrCodeTimeout, "Command timed out.", runCtx.Err())
	case runErr := <-done:
		stdoutW.flush()
		stderrW.flush()
		result := CommandResult{Stdout: full.String(), Duration: time.Since(start)}
		var exitErr *ssh.ExitError
		switch {
		case runErr == nil:
			result.ExitCode = 0
		case errors.As(runErr, &exitErr):
			result.ExitCode = exitErr.ExitStatus()
		default:
			result.ExitCode = -1
			return result, fmt.Errorf("run command: %w", runErr)
		}
		return result, nil
	}
}
