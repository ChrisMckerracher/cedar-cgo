package entity

import (
	context "context"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Remove deletes entities and native edges to them, then recomputes ancestry.
// It preserves the original snapshot and does not modify entity-valued attributes.
func (s ParsedEntityStore) Remove(ctx context.Context, uids ...entityuid.EntityUID) (ParsedEntityStore, error) {
	remove := make([]wire.UID, len(uids))
	for i, uid := range uids {
		remove[i] = uid.Wire()
	}
	// A non-nil empty array distinguishes an empty removal from a missing input.
	result, err := s.call(ctx, EntityStoreInput{Operation: "remove", Remove: &remove})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return s.rt.decodeEntitySnapshot(result)
}

// Upsert replaces matching UIDs and adds new entities with native schema validation.
// If additions contain duplicate UIDs, the last entity wins, as in native Cedar.
func (s ParsedEntityStore) Upsert(ctx context.Context, additions Entities) (ParsedEntityStore, error) {
	result, err := s.call(ctx, EntityStoreInput{Operation: "upsert", Entities: &additions})
	if err != nil {
		return ParsedEntityStore{}, err
	}
	return s.rt.decodeEntitySnapshot(result)
}
