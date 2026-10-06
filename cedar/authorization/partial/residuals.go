package partial

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	jsonv2 "encoding/json/v2"
	partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	syntax "github.com/ChrisMckerracher/cedar-go-wasm/cedar/syntax"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

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
	authorizer *Client
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
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "partial response has no continuation"}
	}
	return jsonv2.Marshal(PartialExport{ResidualProjectionVersion, syntax.CedarVersion, r.input, r.projection})
}

type PartialExport struct {
	Version      uint32             `json:"version"`
	CedarVersion string             `json:"cedar_version"`
	Partial      json.RawMessage    `json:"partial"`
	Projection   ResidualProjection `json:"projection"`
}

// ImportPartialResponse checks an export against native evaluation in this authorizer.
// Different policies, schemas, known inputs, or edited residuals can reject the export.
func (a *Client) ImportPartialResponse(ctx context.Context, data []byte) (PartialResponse, error) {
	if len(data) > a.session.Limits.MaxRequestBytes {
		return PartialResponse{}, diagnostic.LimitError("partial export", len(data), a.session.Limits.MaxRequestBytes)
	}
	if err := wire.CheckUTF8(string(data)); err != nil {
		return PartialResponse{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	var exported PartialExport
	if err := jsonv2.Unmarshal(data, &exported); err != nil {
		return PartialResponse{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: err.Error()}
	}
	if exported.Version != ResidualProjectionVersion || exported.CedarVersion != syntax.CedarVersion {
		return PartialResponse{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "unsupported partial export or Cedar version"}
	}
	var response PartialResponse
	err := a.session.Call(ctx, "cgw_import_partial", data, func(out []byte) error {
		var err error
		response, err = DecodePartial(out)
		return err
	})
	if err != nil {
		return PartialResponse{}, err
	}
	response.authorizer, response.input = a, bytes.Clone(exported.Partial)
	return response, nil
}

type PartialInput struct {
	Principal partialinput.PartialEntityUID `json:"principal"`
	Action    wire.UID                      `json:"action"`
	Resource  partialinput.PartialEntityUID `json:"resource"`
	Context   *request.Context              `json:"context"`
	Entities  partialinput.PartialEntities  `json:"entities"`
}
