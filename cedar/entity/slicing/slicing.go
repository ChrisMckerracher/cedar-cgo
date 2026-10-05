package slicing

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	schema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// DefaultSliceIterations bounds Cedar's entity-loading rounds for a slice.
const DefaultSliceIterations uint32 = 32

// KindSlicing reports TPE validation or iteration exhaustion from Cedar's loader.
const KindSlicing diagnostic.ErrorKind = "slicing"

// SliceConfig configures experimental request-specific whole-entity slicing.
type SliceConfig struct {
	Schema   schema.Schema
	Policies policy.PolicySet
	Entities entity.Entities
	// MaxIterations bounds loader rounds; zero selects DefaultSliceIterations.
	MaxIterations uint32
}

// SliceResult is specific to the original schema, policies, request and entity snapshot.
// It is experimental and does not describe required attributes for other requests.
type SliceResult struct {
	Decision request.Decision
	// Entities retains complete attributes, tags and transitive ancestors of loaded entities.
	// Schema action entities are supplied by the schema when this slice is reused.
	Entities entity.Entities
	// Batches records sorted requested UIDs per loader round, including nonexistent entities.
	Batches [][]entityuid.EntityUID
}

type SliceInput struct {
	Schema        wire.Source            `json:"schema"`
	Policies      wire.Source            `json:"policies"`
	Entities      entity.Entities        `json:"entities"`
	Request       request.AuthorizeInput `json:"request"`
	MaxIterations uint32                 `json:"max_iterations"`
}

type SliceOutput struct {
	Decision string          `json:"decision"`
	Entities json.RawMessage `json:"entities"`
	Batches  [][]wire.UID    `json:"batches"`
	Error    *wire.Error     `json:"error"`
}

// SliceEntities uses Cedar 4.13.0's experimental TPE loader to select whole entities
// from a complete source snapshot. Request.Entities is merged with cfg.Entities.
// The caller's context bounds execution; WithMaxSourceBytes bounds the whole input.
func (rt *Client) SliceEntities(ctx context.Context, cfg SliceConfig, req request.Request) (decoded SliceResult, decodeErr error) {
	iterations := cfg.MaxIterations
	if iterations == 0 {
		iterations = DefaultSliceIterations
	}
	in, err := execution.Encode(SliceInput{
		Schema: cfg.Schema.Wire(), Policies: cfg.Policies.Wire(), Entities: cfg.Entities,
		Request: request.AuthorizeInput{Principal: req.Principal.Wire(), Action: req.Action.Wire(),
			Resource: req.Resource.Wire(), Context: req.Context, Entities: req.Entities},
		MaxIterations: iterations,
	}, "slicing input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return SliceResult{}, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	out, err := rt.runtime.CallOnce(ctx, "cgw_slice_entities", in)
	if err != nil {
		return SliceResult{}, err
	}
	return DecodeSlice(out)
}

func DecodeSlice(out []byte) (SliceResult, error) {
	var w SliceOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return SliceResult{}, diagnostic.FaultError(fmt.Errorf("decode slicing response: %w", err))
	}
	if w.Error != nil {
		return SliceResult{}, diagnostic.ModuleError(w.Error)
	}
	var decision request.Decision
	switch w.Decision {
	case "allow":
		decision = request.Allow
	case "deny":
		decision = request.Deny
	default:
		return SliceResult{}, diagnostic.FaultError(fmt.Errorf("slicing response has decision %q", w.Decision))
	}
	var entities []json.RawMessage
	if len(w.Entities) == 0 || string(w.Entities) == "null" || json.Unmarshal(w.Entities, &entities) != nil || w.Batches == nil {
		return SliceResult{}, diagnostic.FaultError(fmt.Errorf("slicing response has no entity array or batches"))
	}
	batches := make([][]entityuid.EntityUID, len(w.Batches))
	for i, batch := range w.Batches {
		batches[i] = make([]entityuid.EntityUID, len(batch))
		for j, uid := range batch {
			batches[i][j] = entityuid.NewEntityUID(uid.Type, uid.ID)
		}
	}
	return SliceResult{Decision: decision, Entities: entity.EntitiesFromJSON(w.Entities), Batches: batches}, nil
}
