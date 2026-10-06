package execution_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/validation"
	"github.com/ChrisMckerracher/cedar-cgo/internal/execution"
)

func TestDecodeCancellationClearsStrictResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	result, err := validation.DecodeValidation([]byte(`{"passed":true,"errors":[],"warnings":[],"schema_warnings":[]}`), 0, 0)
	if err != nil || !result.Passed {
		t.Fatalf("strict result before cancellation: %+v, %v", result, err)
	}
	cancel()
	execution.FinishDecode(ctx, &result, &err)
	if result.Passed || result.Errors != nil || result.Warnings != nil || result.SchemaWarnings != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("strict result after cancellation: %+v, %v", result, err)
	}
}

func TestDecodeCompletionPreservesErrorsAndClearsLookup(t *testing.T) {
	inputErr := &diagnostic.Error{Kind: diagnostic.KindInput, Message: "invalid response"}
	if got := execution.CompletionError(context.Background(), inputErr); got != inputErr {
		t.Fatalf("uncanceled error changed: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, found, err := request.Response{Decision: request.Allow, Reasons: []string{"policy0"}}, true, error(inputErr)
	execution.FinishLookup(ctx, &result, &found, &err)
	if found || result.Decision != request.Deny || result.Reasons != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("canceled lookup: %+v, found=%t, error=%v", result, found, err)
	}
	result, found, err = request.Response{Decision: request.Allow}, true, nil
	execution.FinishLookup(context.Background(), &result, &found, &err)
	if err != nil || !found || result.Decision != request.Allow {
		t.Fatalf("successful lookup changed: %+v, found=%t, error=%v", result, found, err)
	}
}
