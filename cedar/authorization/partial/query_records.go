package partial

import (
	json "encoding/json"
	fmt "fmt"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// ResourceQueryRequest selects allowed resources from the native entity store.
// All inputs except the resource ID are concrete.
type ResourceQueryRequest struct {
	Principal, Action entityuid.EntityUID
	ResourceType      string
	Context           request.Context
	Entities          entity.Entities
}

// PrincipalQueryRequest selects allowed principals from the native entity store.
// All inputs except the principal ID are concrete.
type PrincipalQueryRequest struct {
	PrincipalType    string
	Action, Resource entityuid.EntityUID
	Context          request.Context
	Entities         entity.Entities
}

// ActionQueryRequest leaves the action unknown. Nil Context is wholly unknown.
// Entity IDs can be unknown; their types must be known.
type ActionQueryRequest struct {
	Principal, Resource PartialEntityUID
	Context             *request.Context
	Entities            PartialEntities
}

// ActionQueryResult separates definite permission from unresolved permission.
// Undecided does not prove that a satisfying completion exists. Denied actions are excluded.
type ActionQueryResult struct {
	Allowed   []entityuid.EntityUID `json:"allowed"`
	Undecided []entityuid.EntityUID `json:"undecided"`
}

// MarshalJSON preserves the flat UID form used by native query results.
func (r ActionQueryResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Allowed   []wire.UID `json:"allowed"`
		Undecided []wire.UID `json:"undecided"`
	}{entityuid.MetadataUIDs(r.Allowed), entityuid.MetadataUIDs(r.Undecided)})
}

func DecodeQueryUIDs(raw *json.RawMessage) ([]entityuid.EntityUID, error) {
	if raw == nil {
		return nil, fmt.Errorf("query response has no candidate list")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(*raw, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, fmt.Errorf("query candidate list is null")
	}
	result := make([]entityuid.EntityUID, len(values))
	seen := map[entityuid.EntityUID]bool{}
	for i, value := range values {
		var uid struct{ Type, ID *string }
		if err := json.Unmarshal(value, &uid); err != nil {
			return nil, err
		}
		if uid.Type == nil || uid.ID == nil || *uid.Type == "" {
			return nil, fmt.Errorf("query candidate has no identity")
		}
		result[i] = entityuid.NewEntityUID(*uid.Type, *uid.ID)
		if seen[result[i]] {
			return nil, fmt.Errorf("duplicate query candidate")
		}
		seen[result[i]] = true
	}
	return result, nil
}

func DecodeQuery(data []byte, action bool) (ActionQueryResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return ActionQueryResult{}, diagnostic.FaultError(err)
	}
	var response struct {
		Allowed, Undecided *json.RawMessage
		Error              *wire.Error
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return ActionQueryResult{}, diagnostic.FaultError(fmt.Errorf("decode query response: %w", err))
	}
	if response.Error != nil {
		return ActionQueryResult{}, diagnostic.ModuleError(response.Error)
	}
	allowed, err := DecodeQueryUIDs(response.Allowed)
	if err != nil {
		return ActionQueryResult{}, diagnostic.FaultError(err)
	}
	result := ActionQueryResult{Allowed: allowed}
	if action {
		result.Undecided, err = DecodeQueryUIDs(response.Undecided)
		if err != nil {
			return ActionQueryResult{}, diagnostic.FaultError(err)
		}
	}
	seen := map[entityuid.EntityUID]bool{}
	for _, uid := range result.Allowed {
		seen[uid] = true
	}
	for _, uid := range result.Undecided {
		if seen[uid] {
			return ActionQueryResult{}, diagnostic.FaultError(fmt.Errorf("query candidate has conflicting states"))
		}
	}
	return result, nil
}
