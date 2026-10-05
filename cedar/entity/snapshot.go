package entity

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	bytes "bytes"
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
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
func (s ParsedEntityStore) Export() Entities { return EntitiesFromJSON(s.normalized) }

// ParseEntityStore parses and validates entities with native Cedar.
// If schema is non-nil, Cedar validates entities and inserts schema action entities.
func (rt *Client) ParseEntityStore(ctx context.Context, entities Entities, schema SchemaSource) (ParsedEntityStore, error) {
	var source *wire.Source
	if hasSchema(schema) {
		value := schema.Wire()
		source = &value
	}
	result, err := rt.entityStoreCall(ctx, EntityStoreInput{Operation: "parse", Entities: &entities, Schema: source})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return rt.decodeEntitySnapshot(result)
}

type EntityStoreInput struct {
	Operation string          `json:"operation"`
	Schema    *wire.Source    `json:"schema,omitempty"`
	Entities  *Entities       `json:"entities,omitempty"`
	Snapshot  json.RawMessage `json:"snapshot,omitempty"`
	Other     json.RawMessage `json:"other,omitempty"`
	UID       *wire.UID       `json:"uid,omitempty"`
	Ancestor  *wire.UID       `json:"ancestor,omitempty"`
	Remove    *[]wire.UID     `json:"remove,omitempty"`
}

type EntityStoreOutput struct {
	Snapshot   json.RawMessage `json:"snapshot"`
	Normalized json.RawMessage `json:"normalized"`
	Entity     json.RawMessage `json:"entity"`
	Ancestors  json.RawMessage `json:"ancestors"`
	Answer     *bool           `json:"answer"`
	Error      *wire.Error     `json:"error"`
}

func (rt *Client) entityStoreCall(ctx context.Context, input EntityStoreInput) (EntityStoreOutput, error) {
	in, err := execution.Encode(input, "entity store input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return EntityStoreOutput{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_entity_store", in)
	if err != nil {
		return EntityStoreOutput{}, err
	}
	var result EntityStoreOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return result, diagnostic.FaultError(fmt.Errorf("decode entity store response: %w", err))
	}
	if result.Error != nil {
		return result, diagnostic.ModuleError(result.Error)
	}
	return result, nil
}

func (rt *Client) decodeEntitySnapshot(result EntityStoreOutput) (ParsedEntityStore, error) {
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

func (s ParsedEntityStore) call(ctx context.Context, input EntityStoreInput) (EntityStoreOutput, error) {
	if s.rt == nil || len(s.snapshot) == 0 {
		return EntityStoreOutput{}, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "zero ParsedEntityStore is invalid"}
	}
	input.Snapshot = s.snapshot
	return s.rt.entityStoreCall(ctx, input)
}
