package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// EntityLiteralInventory lists sorted literal occurrences by policy or template ID.
// Slot bindings are available through Runtime.TemplateLinks. String literals remain strings.
type EntityLiteralInventory struct {
	Policies  map[string][]EntityUID `json:"policies"`
	Templates map[string][]EntityUID `json:"templates"`
}

// MarshalJSON retains flat entity identities and raw policy IDs in metadata.
func (inventory EntityLiteralInventory) MarshalJSON() ([]byte, error) {
	convert := func(entries map[string][]EntityUID) (map[string][]wire.UID, error) {
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
					uids[i] = value.wire()
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

type literalReplacement struct {
	From wire.UID `json:"from"`
	To   wire.UID `json:"to"`
}
type literalOutput struct {
	Inventory *EntityLiteralInventory `json:"inventory"`
	Policies  json.RawMessage         `json:"policies"`
	Error     *wire.Error             `json:"error"`
}

func (rt *Runtime) literalCall(ctx context.Context, operation string, policies PolicySet, replacements map[EntityUID]EntityUID) (literalOutput, error) {
	entries := make([]literalReplacement, 0, len(replacements))
	for from, to := range replacements {
		entries = append(entries, literalReplacement{from.wire(), to.wire()})
	}
	slices.SortFunc(entries, func(a, b literalReplacement) int {
		if c := strings.Compare(a.From.Type, b.From.Type); c != 0 {
			return c
		}
		return strings.Compare(a.From.ID, b.From.ID)
	})
	in, err := json.Marshal(struct {
		Operation    string               `json:"operation"`
		Policies     wire.Source          `json:"policies"`
		Replacements []literalReplacement `json:"replacements"`
	}{operation, policies.wire(), entries})
	if err != nil {
		return literalOutput{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return literalOutput{}, limitError("entity literal input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_literals", in)
	if err != nil {
		return literalOutput{}, err
	}
	var result literalOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return literalOutput{}, faultError(fmt.Errorf("decode entity literal response: %w", err))
	}
	if result.Error != nil {
		return literalOutput{}, moduleError(result.Error)
	}
	return result, nil
}

// EntityLiterals inspects concrete entity references in policies and templates.
func (rt *Runtime) EntityLiterals(ctx context.Context, policies PolicySet) (EntityLiteralInventory, error) {
	result, err := rt.literalCall(ctx, "inspect", policies, nil)
	if err != nil {
		return EntityLiteralInventory{}, err
	}
	if result.Inventory == nil || result.Inventory.Policies == nil || result.Inventory.Templates == nil {
		return EntityLiteralInventory{}, faultError(fmt.Errorf("entity literal response has no inventory"))
	}
	return *result.Inventory, nil
}

// SubstituteEntityLiterals applies all replacements simultaneously through native Cedar.
// Policy IDs, template IDs, annotations, slots, and links retain their identities.
func (rt *Runtime) SubstituteEntityLiterals(ctx context.Context, policies PolicySet, replacements map[EntityUID]EntityUID) (PolicySet, error) {
	result, err := rt.literalCall(ctx, "substitute", policies, replacements)
	if err != nil {
		return PolicySet{}, err
	}
	if len(result.Policies) == 0 || string(result.Policies) == "null" {
		return PolicySet{}, faultError(fmt.Errorf("entity literal response has no policies"))
	}
	return PoliciesFromJSON(result.Policies), nil
}
