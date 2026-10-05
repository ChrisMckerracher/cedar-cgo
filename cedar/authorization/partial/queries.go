package partial

import (
	context "context"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func (a *Client) query(ctx context.Context, input any, action bool) (ActionQueryResult, error) {
	in, err := execution.Encode(input, "request", a.session.Limits.MaxRequestBytes)
	if err != nil {
		return ActionQueryResult{}, err
	}
	var result ActionQueryResult
	err = a.partialCall(ctx, "cgw_queries", in, func(data []byte) error { var err error; result, err = DecodeQuery(data, action); return err })
	if err != nil {
		return ActionQueryResult{}, err
	}
	return result, nil
}

// QueryResources uses Cedar's experimental native resource permission query.
func (a *Client) QueryResources(ctx context.Context, req ResourceQueryRequest) ([]entityuid.EntityUID, error) {
	if err := wire.CheckUTF8(req.ResourceType); err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	result, err := a.query(ctx, struct {
		Operation    string          `json:"operation"`
		Principal    wire.UID        `json:"principal"`
		Action       wire.UID        `json:"action"`
		ResourceType string          `json:"resource_type"`
		Context      request.Context `json:"context"`
		Entities     entity.Entities `json:"entities"`
	}{"resource", req.Principal.Wire(), req.Action.Wire(), req.ResourceType, req.Context, req.Entities}, false)
	return result.Allowed, err
}

// QueryPrincipals uses Cedar's experimental native principal permission query.
func (a *Client) QueryPrincipals(ctx context.Context, req PrincipalQueryRequest) ([]entityuid.EntityUID, error) {
	if err := wire.CheckUTF8(req.PrincipalType); err != nil {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	result, err := a.query(ctx, struct {
		Operation     string          `json:"operation"`
		PrincipalType string          `json:"principal_type"`
		Action        wire.UID        `json:"action"`
		Resource      wire.UID        `json:"resource"`
		Context       request.Context `json:"context"`
		Entities      entity.Entities `json:"entities"`
	}{"principal", req.PrincipalType, req.Action.Wire(), req.Resource.Wire(), req.Context, req.Entities}, false)
	return result.Allowed, err
}

// QueryActions enumerates actions in the schema through Cedar's experimental native query.
func (a *Client) QueryActions(ctx context.Context, req ActionQueryRequest) (ActionQueryResult, error) {
	return a.query(ctx, struct {
		Operation string           `json:"operation"`
		Principal PartialEntityUID `json:"principal"`
		Resource  PartialEntityUID `json:"resource"`
		Context   *request.Context `json:"context"`
		Entities  PartialEntities  `json:"entities"`
	}{"action", req.Principal, req.Resource, req.Context, req.Entities}, true)
}
