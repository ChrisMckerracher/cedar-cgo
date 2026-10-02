package cedar

import (
	"errors"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// ErrorKind classifies an [Error].
type ErrorKind string

// Error kinds. Cedar reports the kinds from KindSchema to KindInput; this
// package reports KindLimit and KindFault.
const (
	KindSchema    ErrorKind = "schema"    // The schema does not parse.
	KindPolicies  ErrorKind = "policies"  // The policies do not parse.
	KindEntities  ErrorKind = "entities"  // The entities do not parse or do not match the schema.
	KindContext   ErrorKind = "context"   // The context does not parse or does not match the schema.
	KindRequest   ErrorKind = "request"   // The request does not match the schema.
	KindPrincipal ErrorKind = "principal" // The principal UID does not parse.
	KindAction    ErrorKind = "action"    // The action UID does not parse.
	KindResource  ErrorKind = "resource"  // The resource UID does not parse.
	KindInput     ErrorKind = "input"     // The module rejected the input envelope.
	KindLimit     ErrorKind = "limit"     // An input exceeds a configured size limit.
	KindFault     ErrorKind = "fault"     // The module trapped, exited, timed out or broke the ABI.
)

// Error is an error from Cedar or from this package. Every Authorize call
// that returns an Error returns the Deny decision.
type Error struct {
	Kind    ErrorKind
	Message string
	// Err is the cause of a KindFault error. A timeout unwraps to
	// context.DeadlineExceeded.
	Err error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cedar: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("cedar: %s: %s", e.Kind, e.Message)
}

// Unwrap returns the cause of a KindFault error.
func (e *Error) Unwrap() error { return e.Err }

// ErrFault matches every KindFault error with [errors.Is].
var ErrFault = errors.New("cedar: module fault")

// Is reports whether target is [ErrFault] and e is a fault.
func (e *Error) Is(target error) bool { return target == ErrFault && e.Kind == KindFault }

func faultError(err error) *Error {
	return &Error{Kind: KindFault, Message: err.Error(), Err: err}
}

func limitError(what string, n, limit int) *Error {
	return &Error{Kind: KindLimit, Message: fmt.Sprintf("%s is %d bytes, above the limit of %d", what, n, limit)}
}

// moduleError converts a module error. A kind that Cedar does not report,
// such as "internal", becomes a fault.
func moduleError(w *wire.Error) *Error {
	switch k := ErrorKind(w.Kind); k {
	case KindSchema, KindPolicies, KindEntities, KindContext, KindRequest,
		KindPrincipal, KindAction, KindResource, KindInput:
		return &Error{Kind: k, Message: w.Message}
	}
	return faultError(fmt.Errorf("module error %q: %s", w.Kind, w.Message))
}
