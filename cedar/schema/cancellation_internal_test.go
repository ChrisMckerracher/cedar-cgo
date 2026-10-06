package schema

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-cgo/internal/execution"
)

type cancelSchemaDecode struct {
	cancel  context.CancelFunc
	decoded bool
}

func (result *cancelSchemaDecode) UnmarshalJSON([]byte) error {
	result.decoded = true
	result.cancel()
	return nil
}

func TestSchemaOperationCancellationDuringDecode(t *testing.T) {
	background := context.Background()
	runtime, err := execution.New(background)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(background)
	ctx, cancel := context.WithCancel(background)
	defer cancel()
	result := cancelSchemaDecode{cancel: cancel}
	err = New(runtime).schemaOperation(ctx, map[string]any{"op": "actions", "schema": SchemaFromCedar(`entity User; action "view" appliesTo { principal: [User], resource: [User], context: {} };`).Wire()}, &result)
	if !result.decoded || !errors.Is(err, context.Canceled) || !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("stateless cancellation: decoded=%t, error=%v", result.decoded, err)
	}
}
