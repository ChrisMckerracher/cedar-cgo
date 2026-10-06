package authorization

import (
	context "context"

	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	partial "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
	query "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/query"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"

	schema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type loadInput struct {
	Schema   *wire.Source    `json:"schema"`
	Policies wire.Source     `json:"policies"`
	Entities entity.Entities `json:"entities,omitzero"`
}

// Authorizer permits concurrent calls. Each pooled native handle owns parsed configuration.
// Close invalidates ordinary, batched, and partial clients, including their continuations.
type Authorizer struct {
	session *execution.Session
}

func NewAuthorizer(ctx context.Context, rt *execution.Runtime, cfg Config) (*Authorizer, error) {
	load, err := execution.Encode(loadInput{Schema: schema.OptionalSchema(cfg.Schema), Policies: cfg.Policies.Wire(), Entities: cfg.Entities}, "schema, policies and entities", rt.MaxSourceBytes)
	if err != nil {
		return nil, err
	}
	s, err := execution.NewSession(ctx, rt, load, cfg.Limits)
	if err != nil {
		return nil, err
	}
	return &Authorizer{session: s}, nil
}

// Authorize returns Deny on every error so callers fail closed.
func (a *Authorizer) Authorize(ctx context.Context, req request.Request) (request.Response, error) {
	return a.authorize(ctx, req, request.DecodeAuthorize)
}

func (a *Authorizer) authorize(ctx context.Context, req request.Request, decode func([]byte) (request.Response, error)) (resp request.Response, err error) {
	in, err := execution.Encode(request.AuthorizeInput{
		Principal: req.Principal.Wire(),
		Action:    req.Action.Wire(),
		Resource:  req.Resource.Wire(),
		Context:   req.Context,
		Entities:  req.Entities,
	}, "request", a.session.Limits.MaxRequestBytes)
	if err != nil {
		return request.Response{}, err
	}
	defer execution.FinishDecode(ctx, &resp, &err)
	err = a.session.Call(ctx, "cgw_authorize", in, func(out []byte) error { var err error; resp, err = decode(out); return err })
	return resp, err
}

// Close waits for active calls before it releases the shared session.
func (a *Authorizer) Close() { a.session.Close() }

func (a *Authorizer) Batched() *batched.Client { return batched.New(a.session) }
func (a *Authorizer) Partial() *partial.Client { return partial.New(a.session) }

func (a *Authorizer) Queries() *query.Client { return query.New(a.session) }

func (a *Authorizer) Stats() Stats { return a.session.Stats() }
