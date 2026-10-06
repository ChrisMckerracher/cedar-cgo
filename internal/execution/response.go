package execution

import (
	"context"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
)

// CompletionError rejects cancellation during Go decoding, after native execution has returned.
func CompletionError(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		return diagnostic.FaultError(cause)
	}
	return err
}

// FinishDecode clears decoded data on failure and preserves the cancellation cause.
func FinishDecode[T any](ctx context.Context, result *T, err *error) {
	*err = CompletionError(ctx, *err)
	if *err != nil {
		var zero T
		*result = zero
	}
}

// FinishLookup also clears the presence flag when decoding fails.
func FinishLookup[T any](ctx context.Context, result *T, found *bool, err *error) {
	FinishDecode(ctx, result, err)
	if *err != nil {
		*found = false
	}
}
