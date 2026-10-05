package solver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSolverExitHelper(t *testing.T) {
	if os.Getenv("CGW_ANALYSIS_EXIT_HELPER") == "1" {
		os.Exit(0)
	}
}

func exitedSolverProcess(t *testing.T, ctx context.Context, cancelResult error) (*process, <-chan struct{}) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSolverExitHelper$")
	cmd.Env = []string{"CGW_ANALYSIS_EXIT_HELPER=1"}
	canceled := make(chan struct{})
	cmd.Cancel = func() error { close(canceled); return cancelResult }
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	transport := &process{cmd: cmd, stdin: stdin, stdout: stdout}
	t.Cleanup(func() { _ = transport.Close() })
	if _, err := io.Copy(io.Discard, stdout); err != nil {
		t.Fatal(err)
	}
	return transport, canceled
}

func TestSolverSuccessfulExitPreservesCleanupErrors(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "wrapped_cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			var failure error
			if mode == "wrapped_cancel" {
				failure = fmt.Errorf("solver cleanup failed: %w", context.Canceled)
			}
			transport, observed := exitedSolverProcess(t, ctx, failure)
			if mode != "deadline" {
				cancel()
			}
			<-observed
			err := transport.Close()
			if failure == nil && err != nil {
				t.Fatalf("successful exit reported cancellation: %v", err)
			}
			if failure != nil && (!errors.Is(err, failure) || !errors.Is(err, context.Canceled)) {
				t.Fatalf("wrapped cleanup error changed: %v", err)
			}
			if state := transport.cmd.ProcessState; state == nil || !state.Success() {
				t.Fatal("helper did not exit successfully")
			}
		})
	}
}

func TestSolverRepeatedWaitRemainsCleanupError(t *testing.T) {
	transport, _ := exitedSolverProcess(t, context.Background(), nil)
	if err := transport.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := transport.Close(); err == nil || !strings.Contains(err.Error(), "Wait was already called") {
		t.Fatalf("repeated wait error was discarded: %v", err)
	}
}
