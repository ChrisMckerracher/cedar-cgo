package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type exchangeCaller struct {
	output []byte
	cancel context.CancelFunc
	calls  int
}

func (c *exchangeCaller) SourceLimit() int { return 1024 }

func (c *exchangeCaller) CallOnce(context.Context, string, []byte) ([]byte, error) {
	c.calls++
	if c.cancel != nil {
		c.cancel()
	}
	return c.output, nil
}

type exchangeReply struct {
	wire.Response
	Value *string `json:"value"`
}

func TestExchangeClearsRejectedResults(t *testing.T) {
	for _, output := range []string{
		`{"value":"changed","error":{"kind":"input","message":"bad"}}`,
		`{"value":"changed","value":"duplicate"}`,
		`{"value":"changed"} {}`,
	} {
		caller := &exchangeCaller{output: []byte(output)}
		result, err := Exchange[exchangeReply](context.Background(), caller, "operation", "test", struct{}{})
		if err == nil || result.Value != nil || result.Error != nil {
			t.Fatalf("rejected result escaped: %+v, %v", result, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	caller := &exchangeCaller{output: []byte(`{"value":"changed"}`), cancel: cancel}
	result, err := Exchange[exchangeReply](ctx, caller, "operation", "test", struct{}{})
	if !errors.Is(err, context.Canceled) || result.Value != nil {
		t.Fatalf("canceled result escaped: %+v, %v", result, err)
	}
}

func TestExchangeRejectsInputBeforeCall(t *testing.T) {
	caller := &exchangeCaller{}
	_, err := Exchange[exchangeReply](context.Background(), caller, "operation", "test", wire.Source{Text: string([]byte{0xff})})
	classified, ok := errors.AsType[*diagnostic.Error](err)
	if !ok || classified.Kind != diagnostic.KindInput || caller.calls != 0 {
		t.Fatalf("invalid input reached native call: %v, calls=%d", err, caller.calls)
	}
}
