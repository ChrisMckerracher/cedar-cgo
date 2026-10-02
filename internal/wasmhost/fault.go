package wasmhost

import (
	"context"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero/sys"
	"strings"
)

// Fault reports a trap, a guest exit, a timeout or an ABI violation.
type Fault struct {
	Module string
	Op     string
	Err    error
	// Stderr holds the start of the guest's stderr, such as a panic message.
	Stderr string
}

// Error keeps panic diagnostics while omitting wazero's stack trace from routine errors.
func (f *Fault) Error() string {
	cause, _, _ := strings.Cut(f.Err.Error(), "\n")
	msg := fmt.Sprintf("%s module: %s: %s", f.Module, f.Op, cause)
	if f.Stderr != "" {
		msg += ": guest stderr: " + f.Stderr
	}
	return msg
}

// Unwrap preserves [context.DeadlineExceeded] and [context.Canceled] for errors.Is.
func (f *Fault) Unwrap() error {
	var exit *sys.ExitError
	if errors.As(f.Err, &exit) {
		switch exit.ExitCode() {
		case sys.ExitCodeDeadlineExceeded:
			return context.DeadlineExceeded
		case sys.ExitCodeContextCanceled:
			return context.Canceled
		}
	}
	return f.Err
}
