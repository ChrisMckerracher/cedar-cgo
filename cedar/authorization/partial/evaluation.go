package partial

import (
	context "context"
	json "encoding/json"
	"errors"
	fmt "fmt"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	schema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// PartialAuthorize runs Rust TPE, including strict policy validation. It requires
// Config.Schema and applies the authorizer's ordinary request byte limits and deadlines.
func (a *Client) PartialAuthorize(ctx context.Context, req partialinput.PartialRequest) (PartialResponse, error) {
	in, err := execution.Encode(PartialInput{req.Principal, req.Action.Wire(), req.Resource, req.Context, req.Entities}, "request", a.session.Limits.MaxRequestBytes)
	if err != nil {
		return PartialResponse{}, err
	}
	var response PartialResponse
	err = a.session.Call(ctx, "cgw_partial_authorize", in, func(out []byte) error {
		var err error
		response, err = DecodePartial(out)
		return err
	})
	if err != nil {
		return PartialResponse{}, err
	}
	response.authorizer, response.input = a, in
	return response, nil
}

// Reauthorize supplies a complete request and entities consistent with the original
// partial input. The originating authorizer must remain open. Errors return Deny.
// Rust recomputes TPE from the frozen input, then reauthorizes its residual policies.
func (r PartialResponse) Reauthorize(ctx context.Context, req request.Request) (request.Response, error) {
	if r.authorizer == nil || len(r.input) == 0 {
		return request.Response{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "partial response has no continuation"}
	}
	in, err := execution.Encode(struct {
		Partial    json.RawMessage        `json:"partial"`
		Request    request.AuthorizeInput `json:"request"`
		Projection ResidualProjection     `json:"projection"`
	}{r.input, request.AuthorizeInput{Principal: req.Principal.Wire(), Action: req.Action.Wire(), Resource: req.Resource.Wire(), Context: req.Context, Entities: req.Entities}, r.projection}, "request", r.authorizer.session.Limits.MaxRequestBytes)
	if err != nil {
		return request.Response{}, err
	}
	var response request.Response
	err = r.authorizer.session.Call(ctx, "cgw_reauthorize", in, func(out []byte) error {
		var err error
		response, err = request.DecodeAuthorize(out)
		return err
	})
	if err != nil {
		return request.Response{}, err
	}
	return response, nil
}

func DecodePartial(out []byte) (PartialResponse, error) {
	type residualWire struct {
		PolicyID *string       `json:"policy_id"`
		Effect   string        `json:"effect"`
		State    ResidualState `json:"state"`
		Cedar    string        `json:"cedar"`
	}
	var w struct {
		Decision   string              `json:"decision"`
		Reasons    []string            `json:"reasons"`
		Residuals  []residualWire      `json:"residuals"`
		Error      *wire.Error         `json:"error"`
		Projection *ResidualProjection `json:"projection"`
	}
	if err := json.Unmarshal(out, &w); err != nil {
		return PartialResponse{}, diagnostic.FaultError(fmt.Errorf("decode partial response: %w", err))
	}
	if w.Error != nil {
		return PartialResponse{}, diagnostic.ModuleError(w.Error)
	}
	var decision PartialDecision
	switch w.Decision {
	case "undecided":
		decision = Undecided
	case "deny":
		decision = PartialDeny
	case "allow":
		decision = PartialAllow
	default:
		return PartialResponse{}, diagnostic.FaultError(fmt.Errorf("partial response has decision %q", w.Decision))
	}
	if w.Reasons == nil || w.Residuals == nil {
		return PartialResponse{}, diagnostic.FaultError(errors.New("partial response is missing reasons or residuals"))
	}
	if w.Projection == nil || w.Projection.Version != ResidualProjectionVersion || w.Projection.CedarVersion != syntax.CedarVersion || w.Projection.Policies == nil || len(w.Projection.Policies) != len(w.Residuals) {
		return PartialResponse{}, diagnostic.FaultError(errors.New("partial response has no supported residual projection"))
	}
	residuals := make([]ResidualPolicy, len(w.Residuals))
	for i, p := range w.Residuals {
		if p.PolicyID == nil || (p.Effect != "permit" && p.Effect != "forbid") || p.Cedar == "" ||
			(i > 0 && *p.PolicyID <= residuals[i-1].PolicyID) {
			return PartialResponse{}, diagnostic.FaultError(errors.New("partial response has malformed residual policies"))
		}
		switch p.State {
		case ResidualUnknown, ResidualTrue, ResidualFalse, ResidualError:
		default:
			return PartialResponse{}, diagnostic.FaultError(fmt.Errorf("partial response has residual state %q", p.State))
		}
		var projected struct {
			Effect string `json:"effect"`
		}
		policy, ok := w.Projection.Policies[*p.PolicyID]
		if !ok || !schema.JsonObject(policy) || json.Unmarshal(policy, &projected) != nil || projected.Effect != p.Effect {
			return PartialResponse{}, diagnostic.FaultError(errors.New("partial residual projection has an inconsistent policy"))
		}
		residuals[i] = ResidualPolicy{PolicyID: *p.PolicyID, Effect: p.Effect, State: p.State, Cedar: p.Cedar}
	}
	return PartialResponse{Decision: decision, Reasons: w.Reasons, Residuals: residuals, projection: *w.Projection}, nil
}
