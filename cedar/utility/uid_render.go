package utility

import (
	"context"
	"fmt"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

// CedarText renders native Cedar syntax. String remains a Go-quoted log representation.
func (rt *Client) RenderUID(ctx context.Context, u uid.EntityUID) (string, error) {
	result, err := execution.UtilityCall(ctx, rt.runtime, map[string]any{"operation": "render_uid", "uid": u.Wire()})
	if err != nil {
		return "", err
	}
	if result.Text == nil || *result.Text == "" {
		return "", diagnostic.FaultError(fmt.Errorf("UID response has no text"))
	}
	return *result.Text, nil
}
