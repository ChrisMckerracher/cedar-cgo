package diagnostic

import (
	errors "errors"
	fmt "fmt"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

type ErrorKind string

// Kinds distinguish Cedar input errors from bridge resource and protocol failures.
const (
	KindEntityUID  ErrorKind = "entity_uid" // A standalone entity UID does not parse.
	KindExpression ErrorKind = "expression" // Expression parsing or evaluation failed.
	KindSchema     ErrorKind = "schema"     // The schema does not parse.
	KindPolicies   ErrorKind = "policies"   // Policy parsing, editing, or TPE validation failed.
	KindEntities   ErrorKind = "entities"   // The entities do not parse or do not match the schema.
	KindContext    ErrorKind = "context"    // The context does not parse or does not match the schema.
	KindRequest    ErrorKind = "request"    // The request is invalid or inconsistent with partial inputs.
	KindPrincipal  ErrorKind = "principal"  // The principal UID does not parse.
	KindAction     ErrorKind = "action"     // The action UID does not parse.
	KindResource   ErrorKind = "resource"   // The resource UID does not parse.
	KindInput      ErrorKind = "input"      // The module rejected the input envelope.
	KindLimit      ErrorKind = "limit"      // An input or formatted output exceeds a size limit.
	KindFault      ErrorKind = "fault"      // The native state panicked, failed, returned after cancellation, or broke the ABI.
)

// Error always accompanies Deny when returned by Authorize.
type Error struct {
	Kind    ErrorKind
	Message string
	// Err preserves fault causes, including context.DeadlineExceeded for timeouts.
	Err error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cedar: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("cedar: %s: %s", e.Kind, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrFault matches every KindFault error with [errors.Is].
var ErrFault = errors.New("cedar: module fault")

func (e *Error) Is(target error) bool { return target == ErrFault && e.Kind == KindFault }

func FaultError(err error) *Error {
	return &Error{Kind: KindFault, Message: err.Error(), Err: err}
}

func LimitError(what string, n, limit int) *Error {
	return &Error{Kind: KindLimit, Message: fmt.Sprintf("%s is %d bytes, above the limit of %d", what, n, limit)}
}

// Unknown native error kinds are faults so the instance cannot return to the pool.
func ModuleError(w *wire.Error) *Error {
	switch k := ErrorKind(w.Kind); k {
	case KindEntityUID, KindExpression, KindSchema, KindPolicies, KindEntities, KindContext, KindRequest,
		KindPrincipal, KindAction, KindResource, KindInput, KindSlicing:
		return &Error{Kind: k, Message: w.Message}
	}
	return FaultError(fmt.Errorf("module error %q: %s", w.Kind, w.Message))
}

const (
	KindSlicing ErrorKind = "slicing"
	KindLoader  ErrorKind = "loader"
	KindBatched ErrorKind = "batched"
)
