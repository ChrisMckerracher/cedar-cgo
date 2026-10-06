package store

import (
	entity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	schema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"

	bytes "bytes"
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-cgo/internal/wire"
)

// ParsedEntityStore is an immutable native entity graph tied to its Runtime.
// Mutations return new snapshots. Direct parents survive each native operation.
type ParsedEntityStore struct {
	rt         *Client
	snapshot   json.RawMessage
	normalized []byte
}

// ParsedEntity reports native values and both direct and transitive ancestry.
// Ancestors excludes the entity itself; IsAncestorOf includes equality.
type ParsedEntity struct {
	UID       entityuid.EntityUID
	Parents   []entityuid.EntityUID
	Ancestors []entityuid.EntityUID
	Attrs     cedarvalue.EvalRecord
	Tags      cedarvalue.EvalRecord
	json      []byte
}

// JSON returns native normalized entity JSON, with transitive ancestors in parents.
func (e ParsedEntity) JSON() []byte { return bytes.Clone(e.json) }

// Export returns native normalized entity JSON, including transitive ancestor edges.
// Use Remove and Upsert on the snapshot to preserve direct-parent mutation semantics.
func (s ParsedEntityStore) Export() entity.Entities { return entity.EntitiesFromJSON(s.normalized) }

// ParseEntityStore parses and validates entities with native Cedar.
// If schema is non-nil, Cedar validates entities and inserts schema action entities.
func (rt *Client) ParseEntityStore(ctx context.Context, entities entity.Entities, schema *schema.Schema) (decoded ParsedEntityStore, decodeErr error) {
	var source *wire.Source
	if schema != nil {
		value := schema.Wire()
		source = &value
	}
	result, err := rt.entityStoreCall(ctx, storeInput{Operation: "parse", Entities: &entities, Schema: source})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	return rt.decodeEntitySnapshot(result)
}

type storeInput struct {
	Operation string       `json:"operation"`
	Schema    *wire.Source `json:"schema,omitzero"`
	// The interface preserves a supplied empty collection despite Entities.IsZero.
	Entities any             `json:"entities,omitzero"`
	Snapshot json.RawMessage `json:"snapshot,omitempty"`
	Other    json.RawMessage `json:"other,omitempty"`
	UID      *wire.UID       `json:"uid,omitzero"`
	Ancestor *wire.UID       `json:"ancestor,omitzero"`
	Remove   *[]wire.UID     `json:"remove,omitzero"`
}

type storeOutput struct {
	Snapshot   json.RawMessage `json:"snapshot"`
	Normalized json.RawMessage `json:"normalized"`
	Entity     json.RawMessage `json:"entity"`
	Ancestors  json.RawMessage `json:"ancestors"`
	Answer     *bool           `json:"answer"`
	wire.Response
}

func (rt *Client) entityStoreCall(ctx context.Context, input storeInput) (storeOutput, error) {
	return execution.Exchange[storeOutput](ctx, rt.runtime, "cgw_entity_store", "entity store", input)
}

func (rt *Client) decodeEntitySnapshot(result storeOutput) (ParsedEntityStore, error) {
	var snapshot struct {
		Version  uint32            `json:"version"`
		Entities []json.RawMessage `json:"entities"`
	}
	if err := json.Unmarshal(result.Snapshot, &snapshot); err != nil || snapshot.Version != 1 || snapshot.Entities == nil {
		return ParsedEntityStore{}, diagnostic.FaultError(fmt.Errorf("entity store response has no supported snapshot"))
	}
	var normalized []json.RawMessage
	if err := json.Unmarshal(result.Normalized, &normalized); err != nil || normalized == nil {
		return ParsedEntityStore{}, diagnostic.FaultError(fmt.Errorf("entity store response has no normalized array"))
	}
	return ParsedEntityStore{rt: rt, snapshot: bytes.Clone(result.Snapshot), normalized: bytes.Clone(result.Normalized)}, nil
}

func (s ParsedEntityStore) call(ctx context.Context, input storeInput) (storeOutput, error) {
	if s.rt == nil || len(s.snapshot) == 0 {
		return storeOutput{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "zero ParsedEntityStore is invalid"}
	}
	input.Snapshot = s.snapshot
	return s.rt.entityStoreCall(ctx, input)
}
