package policy

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	slices "slices"
	strings "strings"
)

// EntityLiteralInventory lists sorted literal occurrences by policy or template ID.
// The template client supplies slot bindings. String literals remain strings.
type EntityLiteralInventory struct {
	Policies  map[string][]entityuid.EntityUID `json:"policies"`
	Templates map[string][]entityuid.EntityUID `json:"templates"`
}

// MarshalJSON retains flat entity identities and raw policy IDs in metadata.
func (inventory EntityLiteralInventory) MarshalJSON() ([]byte, error) {
	convert := func(entries map[string][]entityuid.EntityUID) (map[string][]wire.UID, error) {
		if entries == nil {
			return nil, nil
		}
		result := make(map[string][]wire.UID, len(entries))
		for id, values := range entries {
			if err := wire.CheckUTF8(id); err != nil {
				return nil, err
			}
			var uids []wire.UID
			if values != nil {
				uids = make([]wire.UID, len(values))
				for i, value := range values {
					uids[i] = value.Wire()
				}
			}
			result[id] = uids
		}
		return result, nil
	}
	policies, err := convert(inventory.Policies)
	if err != nil {
		return nil, err
	}
	templates, err := convert(inventory.Templates)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Policies  map[string][]wire.UID `json:"policies"`
		Templates map[string][]wire.UID `json:"templates"`
	}{policies, templates})
}

type LiteralReplacement struct {
	From wire.UID `json:"from"`
	To   wire.UID `json:"to"`
}

type LiteralOutput struct {
	Inventory *EntityLiteralInventory `json:"inventory"`
	Policies  json.RawMessage         `json:"policies"`
	Error     *wire.Error             `json:"error"`
}

func (rt *Client) literalCall(ctx context.Context, operation string, policies PolicySet, replacements map[entityuid.EntityUID]entityuid.EntityUID) (LiteralOutput, error) {
	entries := make([]LiteralReplacement, 0, len(replacements))
	for from, to := range replacements {
		entries = append(entries, LiteralReplacement{from.Wire(), to.Wire()})
	}
	slices.SortFunc(entries, func(a, b LiteralReplacement) int {
		if c := strings.Compare(a.From.Type, b.From.Type); c != 0 {
			return c
		}
		return strings.Compare(a.From.ID, b.From.ID)
	})
	in, err := execution.Encode(struct {
		Operation    string               `json:"operation"`
		Policies     wire.Source          `json:"policies"`
		Replacements []LiteralReplacement `json:"replacements"`
	}{operation, policies.Wire(), entries}, "entity literal input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return LiteralOutput{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_literals", in)
	if err != nil {
		return LiteralOutput{}, err
	}
	var result LiteralOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return LiteralOutput{}, diagnostic.FaultError(fmt.Errorf("decode entity literal response: %w", err))
	}
	if result.Error != nil {
		return LiteralOutput{}, diagnostic.ModuleError(result.Error)
	}
	return result, nil
}

// EntityLiterals inspects concrete entity references in policies and templates.
func (rt *Client) EntityLiterals(ctx context.Context, policies PolicySet) (EntityLiteralInventory, error) {
	result, err := rt.literalCall(ctx, "inspect", policies, nil)
	if err != nil {
		return EntityLiteralInventory{}, err
	}
	if result.Inventory == nil || result.Inventory.Policies == nil || result.Inventory.Templates == nil {
		return EntityLiteralInventory{}, diagnostic.FaultError(fmt.Errorf("entity literal response has no inventory"))
	}
	return *result.Inventory, nil
}

// SubstituteEntityLiterals applies all replacements simultaneously through native Cedar.
// Policy IDs, template IDs, annotations, slots, and links retain their identities.
func (rt *Client) SubstituteEntityLiterals(ctx context.Context, policies PolicySet, replacements map[entityuid.EntityUID]entityuid.EntityUID) (PolicySet, error) {
	result, err := rt.literalCall(ctx, "substitute", policies, replacements)
	if err != nil {
		return PolicySet{}, err
	}
	if len(result.Policies) == 0 || string(result.Policies) == "null" {
		return PolicySet{}, diagnostic.FaultError(fmt.Errorf("entity literal response has no policies"))
	}
	return PoliciesFromJSON(result.Policies), nil
}
