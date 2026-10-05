package entity

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

func NativeUIDs(values []wire.UID) ([]entityuid.EntityUID, error) {
	result := make([]entityuid.EntityUID, len(values))
	for i, value := range values {
		if value.Type == "" {
			return nil, diagnostic.FaultError(fmt.Errorf("entity store response has an incomplete UID"))
		}
		result[i] = entityuid.NewEntityUID(value.Type, value.ID)
	}
	return result, nil
}

func DecodeEntityRecord(values map[string]json.RawMessage) (cedarvalue.EvalRecord, error) {
	if values == nil {
		return nil, diagnostic.FaultError(fmt.Errorf("entity store response has a null value map"))
	}
	result := make(cedarvalue.EvalRecord, len(values))
	for name, value := range values {
		parsed, err := cedarvalue.DecodeEvalResult(value)
		if err != nil {
			return nil, diagnostic.FaultError(fmt.Errorf("decode entity value: %w", err))
		}
		result[name] = parsed
	}
	return result, nil
}

// Get returns the native entity and reports whether the UID exists.
func (s ParsedEntityStore) Get(ctx context.Context, uid entityuid.EntityUID) (ParsedEntity, bool, error) {
	u := uid.Wire()
	result, err := s.call(ctx, EntityStoreInput{Operation: "get", UID: &u})
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
		return ParsedEntity{}, false, diagnostic.FaultError(fmt.Errorf("entity store response has an incomplete entity"))
	}
	parents, err := NativeUIDs(value.Parents)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	ancestors, err := NativeUIDs(value.Ancestors)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	attrs, err := DecodeEntityRecord(value.Attrs)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	tags, err := DecodeEntityRecord(value.Tags)
	if err != nil {
		return ParsedEntity{}, false, err
	}
	return ParsedEntity{UID: entityuid.NewEntityUID(value.UID.Type, value.UID.ID), Parents: parents, Ancestors: ancestors, Attrs: attrs, Tags: tags, json: bytes.Clone(value.Normalized)}, true, nil
}

// Ancestors returns transitive ancestors and reports whether the UID exists.
func (s ParsedEntityStore) Ancestors(ctx context.Context, uid entityuid.EntityUID) ([]entityuid.EntityUID, bool, error) {
	u := uid.Wire()
	result, err := s.call(ctx, EntityStoreInput{Operation: "ancestors", UID: &u})
	if err != nil {
		return nil, false, err
	}
	if bytes.Equal(result.Ancestors, []byte("null")) {
		return nil, false, nil
	}
	var values []wire.UID
	if err := json.Unmarshal(result.Ancestors, &values); err != nil || values == nil {
		return nil, false, diagnostic.FaultError(fmt.Errorf("entity store response has no ancestor array"))
	}
	ancestors, err := NativeUIDs(values)
	return ancestors, true, err
}

// IsAncestorOf follows native Cedar membership semantics, including equal absent UIDs.
func (s ParsedEntityStore) IsAncestorOf(ctx context.Context, ancestor, descendant entityuid.EntityUID) (bool, error) {
	a, d := ancestor.Wire(), descendant.Wire()
	result, err := s.call(ctx, EntityStoreInput{Operation: "is_ancestor", UID: &d, Ancestor: &a})
	if err != nil {
		return false, err
	}
	if result.Answer == nil {
		return false, diagnostic.FaultError(fmt.Errorf("entity store response has no ancestry answer"))
	}
	return *result.Answer, nil
}

// DeepEqual compares native attributes, tags, UIDs, and transitive ancestry.
// Direct-parent provenance does not affect native deep equality.
func (s ParsedEntityStore) DeepEqual(ctx context.Context, other ParsedEntityStore) (bool, error) {
	if other.rt == nil || len(other.snapshot) == 0 {
		return false, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "zero comparison ParsedEntityStore is invalid"}
	}
	result, err := s.call(ctx, EntityStoreInput{Operation: "equal", Other: other.snapshot})
	if err != nil {
		return false, err
	}
	if result.Answer == nil {
		return false, diagnostic.FaultError(fmt.Errorf("entity store response has no equality answer"))
	}
	return *result.Answer, nil
}
