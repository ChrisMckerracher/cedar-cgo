package cedar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// ResourceQueryRequest selects allowed resources from the native entity store.
// All inputs except the resource ID are concrete.
type ResourceQueryRequest struct {
	Principal, Action EntityUID
	ResourceType      string
	Context           Context
	Entities          Entities
}

// PrincipalQueryRequest selects allowed principals from the native entity store.
// All inputs except the principal ID are concrete.
type PrincipalQueryRequest struct {
	PrincipalType    string
	Action, Resource EntityUID
	Context          Context
	Entities         Entities
}

// ActionQueryRequest leaves the action unknown. Nil Context is wholly unknown.
// Entity IDs can be unknown; their types must be known.
type ActionQueryRequest struct {
	Principal, Resource PartialEntityUID
	Context             *Context
	Entities            PartialEntities
}

// ActionQueryResult separates definite permission from unresolved permission.
// Undecided does not prove that a satisfying completion exists. Denied actions are excluded.
type ActionQueryResult struct {
	Allowed   []EntityUID `json:"allowed"`
	Undecided []EntityUID `json:"undecided"`
}

// MarshalJSON preserves the flat UID form used by native query results.
func (r ActionQueryResult) MarshalJSON() ([]byte, error) {
	uidList := func(entities []EntityUID) []wire.UID {
		if entities == nil {
			return nil
		}
		result := make([]wire.UID, len(entities))
		for i, entity := range entities {
			result[i] = entity.wire()
		}
		return result
	}
	return json.Marshal(struct {
		Allowed   []wire.UID `json:"allowed"`
		Undecided []wire.UID `json:"undecided"`
	}{uidList(r.Allowed), uidList(r.Undecided)})
}

func decodeQueryUIDs(raw *json.RawMessage) ([]EntityUID, error) {
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
	result := make([]EntityUID, len(values))
	seen := map[EntityUID]bool{}
	for i, value := range values {
		var uid struct{ Type, ID *string }
		if err := json.Unmarshal(value, &uid); err != nil {
			return nil, err
		}
		if uid.Type == nil || uid.ID == nil || *uid.Type == "" {
			return nil, fmt.Errorf("query candidate has no identity")
		}
		result[i] = NewEntityUID(*uid.Type, *uid.ID)
		if seen[result[i]] {
			return nil, fmt.Errorf("duplicate query candidate")
		}
		seen[result[i]] = true
	}
	return result, nil
}

func decodeQuery(data []byte, action bool) (ActionQueryResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return ActionQueryResult{}, faultError(err)
	}
	var response struct {
		Allowed, Undecided *json.RawMessage
		Error              *wire.Error
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return ActionQueryResult{}, faultError(fmt.Errorf("decode query response: %w", err))
	}
	if response.Error != nil {
		return ActionQueryResult{}, moduleError(response.Error)
	}
	allowed, err := decodeQueryUIDs(response.Allowed)
	if err != nil {
		return ActionQueryResult{}, faultError(err)
	}
	result := ActionQueryResult{Allowed: allowed}
	if action {
		result.Undecided, err = decodeQueryUIDs(response.Undecided)
		if err != nil {
			return ActionQueryResult{}, faultError(err)
		}
	}
	seen := map[EntityUID]bool{}
	for _, uid := range result.Allowed {
		seen[uid] = true
	}
	for _, uid := range result.Undecided {
		if seen[uid] {
			return ActionQueryResult{}, faultError(fmt.Errorf("query candidate has conflicting states"))
		}
	}
	return result, nil
}

func (a *Authorizer) query(ctx context.Context, input any, action bool) (ActionQueryResult, error) {
	in, err := json.Marshal(input)
	if err != nil {
		return ActionQueryResult{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	var result ActionQueryResult
	err = a.partialCall(ctx, "cgw_queries", in, func(data []byte) error { var err error; result, err = decodeQuery(data, action); return err })
	if err != nil {
		return ActionQueryResult{}, err
	}
	return result, nil
}

// QueryResources uses Cedar's experimental native resource permission query.
func (a *Authorizer) QueryResources(ctx context.Context, req ResourceQueryRequest) ([]EntityUID, error) {
	if err := wire.CheckUTF8(req.ResourceType); err != nil {
		return nil, &Error{Kind: KindInput, Message: err.Error()}
	}
	result, err := a.query(ctx, struct {
		Operation    string   `json:"operation"`
		Principal    wire.UID `json:"principal"`
		Action       wire.UID `json:"action"`
		ResourceType string   `json:"resource_type"`
		Context      Context  `json:"context"`
		Entities     Entities `json:"entities"`
	}{"resource", req.Principal.wire(), req.Action.wire(), req.ResourceType, req.Context, req.Entities}, false)
	return result.Allowed, err
}

// QueryPrincipals uses Cedar's experimental native principal permission query.
func (a *Authorizer) QueryPrincipals(ctx context.Context, req PrincipalQueryRequest) ([]EntityUID, error) {
	if err := wire.CheckUTF8(req.PrincipalType); err != nil {
		return nil, &Error{Kind: KindInput, Message: err.Error()}
	}
	result, err := a.query(ctx, struct {
		Operation     string   `json:"operation"`
		PrincipalType string   `json:"principal_type"`
		Action        wire.UID `json:"action"`
		Resource      wire.UID `json:"resource"`
		Context       Context  `json:"context"`
		Entities      Entities `json:"entities"`
	}{"principal", req.PrincipalType, req.Action.wire(), req.Resource.wire(), req.Context, req.Entities}, false)
	return result.Allowed, err
}

// QueryActions enumerates actions in the schema through Cedar's experimental native query.
func (a *Authorizer) QueryActions(ctx context.Context, req ActionQueryRequest) (ActionQueryResult, error) {
	return a.query(ctx, struct {
		Operation string           `json:"operation"`
		Principal PartialEntityUID `json:"principal"`
		Resource  PartialEntityUID `json:"resource"`
		Context   *Context         `json:"context"`
		Entities  PartialEntities  `json:"entities"`
	}{"action", req.Principal, req.Resource, req.Context, req.Entities}, true)
}
