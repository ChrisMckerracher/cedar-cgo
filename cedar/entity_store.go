package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// ParsedEntityStore is an immutable native entity graph tied to its Runtime.
// Mutations return new snapshots. Direct parents survive each native operation.
type ParsedEntityStore struct {
	rt         *Runtime
	snapshot   json.RawMessage
	normalized []byte
}

// ParsedEntity reports native values and both direct and transitive ancestry.
// Ancestors excludes the entity itself; IsAncestorOf includes equality.
type ParsedEntity struct {
	UID       EntityUID
	Parents   []EntityUID
	Ancestors []EntityUID
	Attrs     EvalRecord
	Tags      EvalRecord
	json      []byte
}

// JSON returns native normalized entity JSON, with transitive ancestors in parents.
func (e ParsedEntity) JSON() []byte { return bytes.Clone(e.json) }

// Export returns native normalized entity JSON, including transitive ancestor edges.
// Use Remove and Upsert on the snapshot to preserve direct-parent mutation semantics.
func (s ParsedEntityStore) Export() Entities { return EntitiesFromJSON(s.normalized) }

// ParseEntityStore parses and validates entities with native Cedar.
// If schema is non-nil, Cedar validates entities and inserts schema action entities.
func (rt *Runtime) ParseEntityStore(ctx context.Context, entities Entities, schema *Schema) (ParsedEntityStore, error) {
	var source *wire.Source
	if schema != nil {
		value := schema.wire()
		source = &value
	}
	result, err := rt.entityStoreCall(ctx, entityStoreInput{Operation: "parse", Entities: &entities, Schema: source})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return rt.decodeEntitySnapshot(result)
}

type entityStoreInput struct {
	Operation string          `json:"operation"`
	Schema    *wire.Source    `json:"schema,omitempty"`
	Entities  *Entities       `json:"entities,omitempty"`
	Snapshot  json.RawMessage `json:"snapshot,omitempty"`
	Other     json.RawMessage `json:"other,omitempty"`
	UID       *wire.UID       `json:"uid,omitempty"`
	Ancestor  *wire.UID       `json:"ancestor,omitempty"`
	Remove    *[]wire.UID     `json:"remove,omitempty"`
}

type entityStoreOutput struct {
	Snapshot   json.RawMessage `json:"snapshot"`
	Normalized json.RawMessage `json:"normalized"`
	Entity     json.RawMessage `json:"entity"`
	Ancestors  json.RawMessage `json:"ancestors"`
	Answer     *bool           `json:"answer"`
	Error      *wire.Error     `json:"error"`
}

func (rt *Runtime) entityStoreCall(ctx context.Context, input entityStoreInput) (entityStoreOutput, error) {
	in, err := json.Marshal(input)
	if err != nil {
		return entityStoreOutput{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return entityStoreOutput{}, limitError("entity store input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_entity_store", in)
	if err != nil {
		return entityStoreOutput{}, err
	}
	var result entityStoreOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return result, faultError(fmt.Errorf("decode entity store response: %w", err))
	}
	if result.Error != nil {
		return result, moduleError(result.Error)
	}
	return result, nil
}

func (rt *Runtime) decodeEntitySnapshot(result entityStoreOutput) (ParsedEntityStore, error) {
	var snapshot struct {
		Version  uint32            `json:"version"`
		Entities []json.RawMessage `json:"entities"`
	}
	if err := json.Unmarshal(result.Snapshot, &snapshot); err != nil || snapshot.Version != 1 || snapshot.Entities == nil {
		return ParsedEntityStore{}, faultError(fmt.Errorf("entity store response has no supported snapshot"))
	}
	var normalized []json.RawMessage
	if err := json.Unmarshal(result.Normalized, &normalized); err != nil || normalized == nil {
		return ParsedEntityStore{}, faultError(fmt.Errorf("entity store response has no normalized array"))
	}
	return ParsedEntityStore{rt: rt, snapshot: bytes.Clone(result.Snapshot), normalized: bytes.Clone(result.Normalized)}, nil
}

func (s ParsedEntityStore) call(ctx context.Context, input entityStoreInput) (entityStoreOutput, error) {
	if s.rt == nil || len(s.snapshot) == 0 {
		return entityStoreOutput{}, &Error{Kind: KindInput, Message: "zero ParsedEntityStore is invalid"}
	}
	input.Snapshot = s.snapshot
	return s.rt.entityStoreCall(ctx, input)
}

func nativeUIDs(values []wire.UID) ([]EntityUID, error) {
	result := make([]EntityUID, len(values))
	for i, value := range values {
		if value.Type == "" {
			return nil, faultError(fmt.Errorf("entity store response has an incomplete UID"))
		}
		result[i] = NewEntityUID(value.Type, value.ID)
	}
	return result, nil
}

func decodeEntityRecord(values map[string]json.RawMessage) (EvalRecord, error) {
	if values == nil {
		return nil, faultError(fmt.Errorf("entity store response has a null value map"))
	}
	result := make(EvalRecord, len(values))
	for name, value := range values {
		parsed, err := decodeEvalResult(value)
		if err != nil {
			return nil, faultError(fmt.Errorf("decode entity value: %w", err))
		}
		result[name] = parsed
	}
	return result, nil
}

// Get returns the native entity and reports whether the UID exists.
func (s ParsedEntityStore) Get(ctx context.Context, uid EntityUID) (ParsedEntity, bool, error) {
	u := uid.wire()
	result, err := s.call(ctx, entityStoreInput{Operation: "get", UID: &u})
	if err != nil {
		return ParsedEntity{}, false, err
	}
	if bytes.Equal(result.Entity, []byte("null")) {
		return ParsedEntity{}, false, nil
	}
	var value struct {
		UID        wire.UID                   `json:"uid"`
		Parents    []wire.UID                 `json:"parents"`
		Ancestors  []wire.UID                 `json:"ancestors"`
		Attrs      map[string]json.RawMessage `json:"attrs"`
		Tags       map[string]json.RawMessage `json:"tags"`
		Normalized json.RawMessage            `json:"normalized"`
	}
	if err := json.Unmarshal(result.Entity, &value); err != nil || value.UID.Type == "" || value.Parents == nil || value.Ancestors == nil || len(value.Normalized) == 0 {
		return ParsedEntity{}, false, faultError(fmt.Errorf("entity store response has an incomplete entity"))
	}
	parents, err := nativeUIDs(value.Parents)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	ancestors, err := nativeUIDs(value.Ancestors)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	attrs, err := decodeEntityRecord(value.Attrs)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	tags, err := decodeEntityRecord(value.Tags)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	return ParsedEntity{UID: NewEntityUID(value.UID.Type, value.UID.ID), Parents: parents, Ancestors: ancestors, Attrs: attrs, Tags: tags, json: bytes.Clone(value.Normalized)}, true, nil
}

// Ancestors returns transitive ancestors and reports whether the UID exists.
func (s ParsedEntityStore) Ancestors(ctx context.Context, uid EntityUID) ([]EntityUID, bool, error) {
	u := uid.wire()
	result, err := s.call(ctx, entityStoreInput{Operation: "ancestors", UID: &u})
	if err != nil {
		return nil, false, err
	}
	if bytes.Equal(result.Ancestors, []byte("null")) {
		return nil, false, nil
	}
	var values []wire.UID
	if err := json.Unmarshal(result.Ancestors, &values); err != nil || values == nil {
		return nil, false, faultError(fmt.Errorf("entity store response has no ancestor array"))
	}
	ancestors, err := nativeUIDs(values)
	return ancestors, true, err
}

// IsAncestorOf follows native Cedar membership semantics, including equal absent UIDs.
func (s ParsedEntityStore) IsAncestorOf(ctx context.Context, ancestor, descendant EntityUID) (bool, error) {
	a, d := ancestor.wire(), descendant.wire()
	result, err := s.call(ctx, entityStoreInput{Operation: "is_ancestor", UID: &d, Ancestor: &a})
	if err != nil {
		return false, err
	}
	if result.Answer == nil {
		return false, faultError(fmt.Errorf("entity store response has no ancestry answer"))
	}
	return *result.Answer, nil
}

// DeepEqual compares native attributes, tags, UIDs, and transitive ancestry.
// Direct-parent provenance does not affect native deep equality.
func (s ParsedEntityStore) DeepEqual(ctx context.Context, other ParsedEntityStore) (bool, error) {
	if other.rt == nil || len(other.snapshot) == 0 {
		return false, &Error{Kind: KindInput, Message: "zero comparison ParsedEntityStore is invalid"}
	}
	result, err := s.call(ctx, entityStoreInput{Operation: "equal", Other: other.snapshot})
	if err != nil {
		return false, err
	}
	if result.Answer == nil {
		return false, faultError(fmt.Errorf("entity store response has no equality answer"))
	}
	return *result.Answer, nil
}

// Remove deletes entities and native edges to them, then recomputes ancestry.
// It preserves the original snapshot and does not modify entity-valued attributes.
func (s ParsedEntityStore) Remove(ctx context.Context, uids ...EntityUID) (ParsedEntityStore, error) {
	remove := make([]wire.UID, len(uids))
	for i, uid := range uids {
		remove[i] = uid.wire()
	}
	// A non-nil empty array distinguishes an empty removal from a missing input.
	result, err := s.call(ctx, entityStoreInput{Operation: "remove", Remove: &remove})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return s.rt.decodeEntitySnapshot(result)
}

// Upsert replaces matching UIDs and adds new entities with native schema validation.
// If additions contain duplicate UIDs, the last entity wins, as in native Cedar.
func (s ParsedEntityStore) Upsert(ctx context.Context, additions Entities) (ParsedEntityStore, error) {
	result, err := s.call(ctx, entityStoreInput{Operation: "upsert", Entities: &additions})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return s.rt.decodeEntitySnapshot(result)
}
