package literal

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	jsonv2 "encoding/json/v2"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
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
	convert := func(entries map[string][]entityuid.EntityUID) map[string][]wire.UID {
		if entries == nil {
			return nil
		}
		result := make(map[string][]wire.UID, len(entries))
		for id, values := range entries {
			result[id] = entityuid.MetadataUIDs(values)
		}
		return result
	}
	policies, templates := convert(inventory.Policies), convert(inventory.Templates)
	return jsonv2.Marshal(struct {
		Policies  map[string][]wire.UID `json:"policies"`
		Templates map[string][]wire.UID `json:"templates"`
	}{policies, templates}, jsonv2.Deterministic(true), jsonv2.FormatNilMapAsNull(true), jsonv2.FormatNilSliceAsNull(true))
}

type literalReplacement struct {
	From wire.UID `json:"from"`
	To   wire.UID `json:"to"`
}

type literalOutput struct {
	Inventory *EntityLiteralInventory `json:"inventory"`
	Policies  json.RawMessage         `json:"policies"`
	wire.Response
}

func (rt *Client) literalCall(ctx context.Context, operation string, policies policy.PolicySet, replacements map[entityuid.EntityUID]entityuid.EntityUID) (decoded literalOutput, decodeErr error) {
	entries := make([]literalReplacement, 0, len(replacements))
	for from, to := range replacements {
		entries = append(entries, literalReplacement{from.Wire(), to.Wire()})
	}
	slices.SortFunc(entries, func(a, b literalReplacement) int {
		if c := strings.Compare(a.From.Type, b.From.Type); c != 0 {
			return c
		}
		return strings.Compare(a.From.ID, b.From.ID)
	})
	return execution.Exchange[literalOutput](ctx, rt.runtime, "cgw_literals", "entity literal", struct {
		Operation    string               `json:"operation"`
		Policies     wire.Source          `json:"policies"`
		Replacements []literalReplacement `json:"replacements"`
	}{operation, policies.Wire(), entries})
}

// EntityLiterals inspects concrete entity references in policies and templates.
func (rt *Client) EntityLiterals(ctx context.Context, policies policy.PolicySet) (EntityLiteralInventory, error) {
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
func (rt *Client) SubstituteEntityLiterals(ctx context.Context, policies policy.PolicySet, replacements map[entityuid.EntityUID]entityuid.EntityUID) (decoded policy.PolicySet, decodeErr error) {
	result, err := rt.literalCall(ctx, "substitute", policies, replacements)
	if err != nil {
		return policy.PolicySet{}, err
	}
	defer execution.FinishDecode(ctx, &decoded, &decodeErr)
	if len(result.Policies) == 0 || string(result.Policies) == "null" {
		return policy.PolicySet{}, diagnostic.FaultError(fmt.Errorf("entity literal response has no policies"))
	}
	return policy.PoliciesFromJSON(result.Policies), nil
}
