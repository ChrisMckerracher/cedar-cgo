package cedar

import (
	"context"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	slicing "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/slicing"
	expression "github.com/ChrisMckerracher/cedar-go-wasm/cedar/expression"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	applicability "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/applicability"
	policyformat "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/format"
	policysource "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/source"
	template "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
	schema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	utility "github.com/ChrisMckerracher/cedar-go-wasm/cedar/utility"
	validation "github.com/ChrisMckerracher/cedar-go-wasm/cedar/validation"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
)

type Runtime struct{ runtime *execution.Runtime }

func NewRuntime(ctx context.Context, opts ...RuntimeOption) (*Runtime, error) {
	rt, e := execution.New(ctx, opts...)
	if e != nil {
		return nil, e
	}
	return &Runtime{runtime: rt}, nil
}
func (rt *Runtime) Close(ctx context.Context) error { return rt.runtime.Close(ctx) }
func (rt *Runtime) NewAuthorizer(ctx context.Context, cfg authorization.Config) (*authorization.Authorizer, error) {
	return authorization.NewAuthorizer(ctx, rt.runtime, cfg)
}
func (rt *Runtime) Applicability() *applicability.Client { return applicability.New(rt.runtime) }
func (rt *Runtime) Schemas() *schema.Client              { return schema.New(rt.runtime) }
func (rt *Runtime) Entities() *entity.Client             { return entity.New(rt.runtime) }
func (rt *Runtime) Expressions() *expression.Client      { return expression.New(rt.runtime) }
func (rt *Runtime) Formatter() *policyformat.Client      { return policyformat.New(rt.runtime) }
func (rt *Runtime) Policies() *policy.Client             { return policy.New(rt.runtime) }
func (rt *Runtime) Slicing() *slicing.Client             { return slicing.New(rt.runtime) }
func (rt *Runtime) Source() *policysource.Client         { return policysource.New(rt.runtime) }
func (rt *Runtime) Templates() *template.Client          { return template.New(rt.runtime) }
func (rt *Runtime) Utilities() *utility.Client           { return utility.New(rt.runtime) }
func (rt *Runtime) Validation() *validation.Client       { return validation.New(rt.runtime) }
