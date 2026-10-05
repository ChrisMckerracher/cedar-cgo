package request

import (
	"context"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
)

type UtilityClient interface {
	ContextValues(context.Context, Context) (value.EvalRecord, error)
	ContextGet(context.Context, Context, string) (value.EvalResult, bool, error)
	ContextMerge(context.Context, Context, Context) (Context, error)
	ContextValidate(context.Context, Context, schema.Schema, uid.EntityUID) error
}

func (c Context) Values(ctx context.Context, client UtilityClient) (value.EvalRecord, error) {
	return client.ContextValues(ctx, c)
}
func (c Context) Get(ctx context.Context, client UtilityClient, key string) (value.EvalResult, bool, error) {
	return client.ContextGet(ctx, c, key)
}
func (c Context) Merge(ctx context.Context, client UtilityClient, other Context) (Context, error) {
	return client.ContextMerge(ctx, c, other)
}
func (c Context) Validate(ctx context.Context, client UtilityClient, s schema.Schema, action uid.EntityUID) error {
	return client.ContextValidate(ctx, c, s, action)
}
