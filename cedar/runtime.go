package cedar

import (
	"context"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	slicing "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/slicing"
	entitystore "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/store"
	expression "github.com/ChrisMckerracher/cedar-cgo/cedar/expression"
	policy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	applicability "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/applicability"
	policyformat "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/format"
	literal "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/literal"
	policysource "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/source"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	schema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	utility "github.com/ChrisMckerracher/cedar-cgo/cedar/utility"
	validation "github.com/ChrisMckerracher/cedar-cgo/cedar/validation"
	"github.com/ChrisMckerracher/cedar-cgo/internal/execution"
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
func (rt *Runtime) EntityStore() *entitystore.Client     { return entitystore.New(rt.runtime) }
func (rt *Runtime) Expressions() *expression.Client      { return expression.New(rt.runtime) }
func (rt *Runtime) Formatter() *policyformat.Client      { return policyformat.New(rt.runtime) }
func (rt *Runtime) Policies() *policy.Client             { return policy.New(rt.runtime) }
func (rt *Runtime) PolicyLiterals() *literal.Client      { return literal.New(rt.runtime) }
func (rt *Runtime) Slicing() *slicing.Client             { return slicing.New(rt.runtime) }
func (rt *Runtime) Source() *policysource.Client         { return policysource.New(rt.runtime) }
func (rt *Runtime) Templates() *template.Client          { return template.New(rt.runtime) }
func (rt *Runtime) Utilities() *utility.Client           { return utility.New(rt.runtime) }
func (rt *Runtime) Validation() *validation.Client       { return validation.New(rt.runtime) }
