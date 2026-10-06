package execution

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Exchange shares stateless encoding, cancellation, and native error-envelope handling.
func Exchange[T interface{ ResponseError() *wire.Error }](ctx context.Context, rt Caller, operation, what string, input any) (decoded T, decodeErr error) {
	in, err := Encode(input, what+" input", rt.SourceLimit())
	if err != nil {
		return decoded, err
	}
	defer FinishDecode(ctx, &decoded, &decodeErr)
	out, err := rt.CallOnce(ctx, operation, in)
	if err != nil {
		return decoded, err
	}
	if err := json.Unmarshal(out, &decoded, json.MatchCaseInsensitiveNames(true)); err != nil {
		return decoded, diagnostic.FaultError(fmt.Errorf("decode %s response: %w", what, err))
	}
	if err := decoded.ResponseError(); err != nil {
		return decoded, diagnostic.ModuleError(err)
	}
	return decoded, nil
}
