package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// PartialDecision is experimental. Its zero value grants no permission.
type PartialDecision int

const (
	Undecided PartialDecision = iota
	PartialDeny
	PartialAllow
)

func (d PartialDecision) String() string {
	switch d {
	case PartialDeny:
		return "deny"
	case PartialAllow:
		return "allow"
	default:
		return "undecided"
	}
}

// PartialEntityUID has a known type and an optional ID. Nil means unknown, not empty.
// This API follows Cedar's experimental type-aware partial evaluation (TPE).
type PartialEntityUID struct {
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

func (u PartialEntityUID) MarshalJSON() ([]byte, error) {
	if err := wire.CheckUTF8(u.Type); err != nil {
		return nil, err
	}
	if u.ID != nil {
		if err := wire.CheckUTF8(*u.ID); err != nil {
			return nil, err
		}
	}
	type uid PartialEntityUID
	return json.Marshal(uid(u))
}

func UnknownEntityUID(typ string) PartialEntityUID { return PartialEntityUID{Type: typ} }

func KnownEntityUID(uid EntityUID) PartialEntityUID {
	return PartialEntityUID{Type: uid.Type, ID: &uid.ID}
}

// PartialEntity permits each complete field to be unknown. Attrs and Tags are
// unknown when nil; Parents is unknown when nil, and known empty when non-nil empty.
type PartialEntity struct {
	UID     EntityUID
	Attrs   *Record
	Parents []EntityUID
	Tags    *Record
}

func (e PartialEntity) MarshalJSON() ([]byte, error) {
	var parents []wire.UID
	if e.Parents != nil {
		parents = make([]wire.UID, len(e.Parents))
		for i, p := range e.Parents {
			parents[i] = p.wire()
		}
	}
	return json.Marshal(struct {
		UID     wire.UID   `json:"uid"`
		Attrs   *Record    `json:"attrs"`
		Parents []wire.UID `json:"parents"`
		Tags    *Record    `json:"tags"`
	}{e.UID.wire(), e.Attrs, parents, e.Tags})
}

// PartialEntities is experimental. Absent entities have unknown data; omitted or
// null attrs, parents, and tags are unknown, while {} and [] are known empty.
type PartialEntities struct {
	list   []PartialEntity
	raw    []byte
	isJSON bool
}

func NewPartialEntities(entities ...PartialEntity) PartialEntities {
	return PartialEntities{list: entities}
}

// PartialEntitiesFromJSON accepts Cedar TPE's entity array. Each attrs, parents,
// and tags field must be wholly known or unknown; ancestors must have known parents.
func PartialEntitiesFromJSON(data []byte) PartialEntities {
	return PartialEntities{raw: bytes.Clone(data), isJSON: true}
}

func (e PartialEntities) MarshalJSON() ([]byte, error) {
	if e.isJSON {
		if err := wire.CheckUTF8(string(e.raw)); err != nil {
			return nil, err
		}
		return e.raw, nil
	}
	if e.list == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(e.list)
}

// PartialRequest is experimental. A schema, principal/resource types, and action
// are required. Context is wholly unknown when nil; a pointer to Context{} is known empty.
type PartialRequest struct {
	Principal PartialEntityUID
	Action    EntityUID
	Resource  PartialEntityUID
	Context   *Context
	// Entities augments loaded concrete entities. Duplicate UIDs are errors.
	Entities PartialEntities
}

// ResidualState distinguishes unevaluated conditions from constant/error residuals.
type ResidualState string

const (
	ResidualUnknown ResidualState = "residual"
	ResidualTrue    ResidualState = "true"
	ResidualFalse   ResidualState = "false"
	ResidualError   ResidualState = "error"
)

// ResidualPolicy is an experimental inspection view. Cedar may include internal
// residual-error expressions that cannot be parsed as ordinary Cedar source.
type ResidualPolicy struct {
	PolicyID string        `json:"policy_id"`
	Effect   string        `json:"effect"`
	State    ResidualState `json:"state"`
	Cedar    string        `json:"cedar"`
}

// PartialResponse is experimental and includes every residual, sorted by policy ID.
// Reauthorization uses a private snapshot; editing these fields cannot grant permission.
type PartialResponse struct {
	Decision   PartialDecision
	Reasons    []string
	Residuals  []ResidualPolicy
	authorizer *Authorizer
	input      json.RawMessage
	projection ResidualProjection
}

// ResidualProjection stores native PST expressions through their Cedar EST mapping.
// The error operator with no arguments preserves nested residual errors.
type ResidualProjection struct {
	Version      uint32                     `json:"version"`
	CedarVersion string                     `json:"cedar_version"`
	Policies     map[string]json.RawMessage `json:"policies"`
}

const ResidualProjectionVersion uint32 = 1

// Projection returns a copy of the native residual representation.
func (r PartialResponse) Projection() ResidualProjection {
	result := ResidualProjection{Version: r.projection.Version, CedarVersion: r.projection.CedarVersion}
	if r.projection.Policies != nil {
		result.Policies = make(map[string]json.RawMessage, len(r.projection.Policies))
		for id, policy := range r.projection.Policies {
			result.Policies[id] = bytes.Clone(policy)
		}
	}
	return result
}

// Export serializes the frozen partial input and native residual projection.
// Changes to public inspection fields do not change the export.
func (r PartialResponse) Export() ([]byte, error) {
	if r.authorizer == nil || len(r.input) == 0 {
		return nil, &Error{Kind: KindInput, Message: "partial response has no continuation"}
	}
	return json.Marshal(partialExport{ResidualProjectionVersion, CedarVersion, r.input, r.projection})
}

type partialExport struct {
	Version      uint32             `json:"version"`
	CedarVersion string             `json:"cedar_version"`
	Partial      json.RawMessage    `json:"partial"`
	Projection   ResidualProjection `json:"projection"`
}

// ImportPartialResponse checks an export against native evaluation in this authorizer.
// Different policies, schemas, known inputs, or edited residuals can reject the export.
func (a *Authorizer) ImportPartialResponse(ctx context.Context, data []byte) (PartialResponse, error) {
	if len(data) > a.limits.MaxRequestBytes {
		return PartialResponse{}, limitError("partial export", len(data), a.limits.MaxRequestBytes)
	}
	if err := wire.CheckUTF8(string(data)); err != nil {
		return PartialResponse{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	var exported partialExport
	if err := json.Unmarshal(data, &exported); err != nil {
		return PartialResponse{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if exported.Version != ResidualProjectionVersion || exported.CedarVersion != CedarVersion {
		return PartialResponse{}, &Error{Kind: KindInput, Message: "unsupported partial export or Cedar version"}
	}
	var response PartialResponse
	err := a.partialCall(ctx, "cgw_import_partial", data, func(out []byte) error {
		var err error
		response, err = decodePartial(out)
		return err
	})
	if err != nil {
		return PartialResponse{}, err
	}
	response.authorizer, response.input = a, bytes.Clone(exported.Partial)
	return response, nil
}

type partialInput struct {
	Principal PartialEntityUID `json:"principal"`
	Action    wire.UID         `json:"action"`
	Resource  PartialEntityUID `json:"resource"`
	Context   *Context         `json:"context"`
	Entities  PartialEntities  `json:"entities"`
}

// PartialAuthorize runs Rust TPE, including strict policy validation. It requires
// Config.Schema and applies the authorizer's ordinary request, time, and memory limits.
func (a *Authorizer) PartialAuthorize(ctx context.Context, req PartialRequest) (PartialResponse, error) {
	in, err := json.Marshal(partialInput{req.Principal, req.Action.wire(), req.Resource, req.Context, req.Entities})
	if err != nil {
		return PartialResponse{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	var response PartialResponse
	err = a.partialCall(ctx, "cgw_partial_authorize", in, func(out []byte) error {
		var err error
		response, err = decodePartial(out)
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
func (r PartialResponse) Reauthorize(ctx context.Context, req Request) (Response, error) {
	if r.authorizer == nil || len(r.input) == 0 {
		return Response{}, &Error{Kind: KindInput, Message: "partial response has no continuation"}
	}
	in, err := json.Marshal(struct {
		Partial    json.RawMessage    `json:"partial"`
		Request    authorizeInput     `json:"request"`
		Projection ResidualProjection `json:"projection"`
	}{r.input, authorizeInput{req.Principal.wire(), req.Action.wire(), req.Resource.wire(), req.Context, req.Entities}, r.projection})
	if err != nil {
		return Response{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	var response Response
	err = r.authorizer.partialCall(ctx, "cgw_reauthorize", in, func(out []byte) error {
		var err error
		response, err = decodeAuthorize(out)
		return err
	})
	if err != nil {
		return Response{}, err
	}
	return response, nil
}

func (a *Authorizer) partialCall(ctx context.Context, op string, in []byte, decode func([]byte) error) error {
	if len(in) > a.limits.MaxRequestBytes {
		return limitError("partial evaluation request", len(in), a.limits.MaxRequestBytes)
	}
	res, err := a.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("cedar: acquire instance: %w", err)
	}
	defer a.finish(res)
	if a.limits.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.limits.CallTimeout)
		defer cancel()
	}
	inst := res.Value()
	out, err := inst.Call(ctx, op, in, a.rt.maxResponse)
	if err != nil {
		return faultError(err)
	}
	err = decode(out)
	var cerr *Error
	if errors.As(err, &cerr) && cerr.Kind == KindFault {
		inst.MarkFaulted()
	}
	return err
}

func decodePartial(out []byte) (PartialResponse, error) {
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
		return PartialResponse{}, faultError(fmt.Errorf("decode partial response: %w", err))
	}
	if w.Error != nil {
		return PartialResponse{}, moduleError(w.Error)
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
		return PartialResponse{}, faultError(fmt.Errorf("partial response has decision %q", w.Decision))
	}
	if w.Reasons == nil || w.Residuals == nil {
		return PartialResponse{}, faultError(errors.New("partial response is missing reasons or residuals"))
	}
	if w.Projection == nil || w.Projection.Version != ResidualProjectionVersion || w.Projection.CedarVersion != CedarVersion || w.Projection.Policies == nil || len(w.Projection.Policies) != len(w.Residuals) {
		return PartialResponse{}, faultError(errors.New("partial response has no supported residual projection"))
	}
	residuals := make([]ResidualPolicy, len(w.Residuals))
	for i, p := range w.Residuals {
		if p.PolicyID == nil || (p.Effect != "permit" && p.Effect != "forbid") || p.Cedar == "" ||
			(i > 0 && *p.PolicyID <= residuals[i-1].PolicyID) {
			return PartialResponse{}, faultError(errors.New("partial response has malformed residual policies"))
		}
		switch p.State {
		case ResidualUnknown, ResidualTrue, ResidualFalse, ResidualError:
		default:
			return PartialResponse{}, faultError(fmt.Errorf("partial response has residual state %q", p.State))
		}
		var projected struct {
			Effect string `json:"effect"`
		}
		policy, ok := w.Projection.Policies[*p.PolicyID]
		if !ok || !jsonObject(policy) || json.Unmarshal(policy, &projected) != nil || projected.Effect != p.Effect {
			return PartialResponse{}, faultError(errors.New("partial residual projection has an inconsistent policy"))
		}
		residuals[i] = ResidualPolicy{PolicyID: *p.PolicyID, Effect: p.Effect, State: p.State, Cedar: p.Cedar}
	}
	return PartialResponse{Decision: decision, Reasons: w.Reasons, Residuals: residuals, projection: *w.Projection}, nil
}
