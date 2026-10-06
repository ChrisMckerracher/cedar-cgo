package partial

import (
	"context"
	"encoding/json"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	"github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	"github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

type TestConfig struct {
	Schema   *schema.Schema
	Policies policy.PolicySet
	Limits   execution.Limits
}

func newClient(ctx context.Context, rt *execution.Runtime, cfg TestConfig) (*Client, error) {
	in, e := json.Marshal(struct {
		Schema   *wire.Source `json:"schema"`
		Policies wire.Source  `json:"policies"`
		Entities []any        `json:"entities"`
	}{schema.OptionalSchema(cfg.Schema), cfg.Policies.Wire(), []any{}})
	if e != nil {
		return nil, e
	}
	s, e := execution.NewSession(ctx, rt, in, cfg.Limits)
	if e != nil {
		return nil, e
	}
	return New(s), nil
}
