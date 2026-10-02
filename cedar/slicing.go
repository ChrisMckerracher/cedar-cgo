package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// DefaultSliceIterations bounds Cedar's entity-loading rounds for a slice.
const DefaultSliceIterations uint32 = 32

// KindSlicing reports TPE validation or iteration exhaustion from Cedar's loader.
const KindSlicing ErrorKind = "slicing"

// SliceConfig configures experimental request-specific whole-entity slicing.
type SliceConfig struct {
	Schema   Schema
	Policies PolicySet
	Entities Entities
	// MaxIterations bounds loader rounds; zero selects DefaultSliceIterations.
	MaxIterations uint32
}

// SliceResult is specific to the original schema, policies, request and entity snapshot.
// It is experimental and does not describe required attributes for other requests.
type SliceResult struct {
	Decision Decision
	// Entities retains complete attributes, tags and transitive ancestors of loaded entities.
	// Schema action entities are supplied by the schema when this slice is reused.
	Entities Entities
	// Batches records sorted requested UIDs per loader round, including nonexistent entities.
	Batches [][]EntityUID
}

type sliceInput struct {
	Schema        wire.Source    `json:"schema"`
	Policies      wire.Source    `json:"policies"`
	Entities      Entities       `json:"entities"`
	Request       authorizeInput `json:"request"`
	MaxIterations uint32         `json:"max_iterations"`
}

type sliceOutput struct {
	Decision string          `json:"decision"`
	Entities json.RawMessage `json:"entities"`
	Batches  [][]wire.UID    `json:"batches"`
	Error    *wire.Error     `json:"error"`
}

// SliceEntities uses Cedar 4.13.0's experimental TPE loader to select whole entities
// from a complete source snapshot. Request.Entities is merged with cfg.Entities.
// The caller's context bounds execution; WithMaxSourceBytes bounds the whole input.
func (rt *Runtime) SliceEntities(ctx context.Context, cfg SliceConfig, req Request) (SliceResult, error) {
	iterations := cfg.MaxIterations
	if iterations == 0 {
		iterations = DefaultSliceIterations
	}
	in, err := json.Marshal(sliceInput{
		Schema: cfg.Schema.wire(), Policies: cfg.Policies.wire(), Entities: cfg.Entities,
		Request: authorizeInput{Principal: req.Principal.wire(), Action: req.Action.wire(),
			Resource: req.Resource.wire(), Context: req.Context, Entities: req.Entities},
		MaxIterations: iterations,
	})
	if err != nil {
		return SliceResult{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return SliceResult{}, limitError("slicing input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_slice_entities", in)
	if err != nil {
		return SliceResult{}, err
	}
	return decodeSlice(out)
}

func decodeSlice(out []byte) (SliceResult, error) {
	var w sliceOutput
	if err := json.Unmarshal(out, &w); err != nil {
		return SliceResult{}, faultError(fmt.Errorf("decode slicing response: %w", err))
	}
	if w.Error != nil {
		return SliceResult{}, moduleError(w.Error)
	}
	var decision Decision
	switch w.Decision {
	case "allow":
		decision = Allow
	case "deny":
		decision = Deny
	default:
		return SliceResult{}, faultError(fmt.Errorf("slicing response has decision %q", w.Decision))
	}
	var entities []json.RawMessage
	if len(w.Entities) == 0 || string(w.Entities) == "null" || json.Unmarshal(w.Entities, &entities) != nil || w.Batches == nil {
		return SliceResult{}, faultError(fmt.Errorf("slicing response has no entity array or batches"))
	}
	batches := make([][]EntityUID, len(w.Batches))
	for i, batch := range w.Batches {
		batches[i] = make([]EntityUID, len(batch))
		for j, uid := range batch {
			batches[i][j] = NewEntityUID(uid.Type, uid.ID)
		}
	}
	return SliceResult{Decision: decision, Entities: EntitiesFromJSON(w.Entities), Batches: batches}, nil
}
