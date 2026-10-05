package source

import (
	"context"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

func newRuntime(ctx context.Context, opts ...execution.Option) (*Client, error) {
	rt, e := execution.New(ctx, opts...)
	if e != nil {
		return nil, e
	}
	return New(rt), nil
}
