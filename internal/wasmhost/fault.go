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

// Error returns the first line of the cause, without wazero's stack trace,
// and the guest's stderr.
func (f *Fault) Error() string {
	cause, _, _ := strings.Cut(f.Err.Error(), "\n")
	msg := fmt.Sprintf("%s module: %s: %s", f.Module, f.Op, cause)
	if f.Stderr != "" {
		msg += ": guest stderr: " + f.Stderr
	}
	return msg
}

// Unwrap returns the cause. A timeout unwraps to [context.DeadlineExceeded]
// and a cancellation to [context.Canceled].
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
