package cedar_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func partialIDPolicy(effect, kind, body string) json.RawMessage {
	return json.RawMessage(`{"effect":"` + effect + `","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"` + kind + `","body":` + body + `}]}`)
}

func partialIDPolicies(t *testing.T, policies map[string]json.RawMessage) cedar.PolicySet {
	t.Helper()
	data, err := json.Marshal(map[string]any{"staticPolicies": policies, "templates": map[string]any{}, "templateLinks": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return cedar.PoliciesFromJSON(data)
}

func TestPartialRawPolicyIDs(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(partialSchema)
	const suffix = "\"\n\\\x00"
	const permitID, forbidID, errorID = "permit" + suffix, "forbid" + suffix, "error" + suffix
	policies := partialIDPolicies(t, map[string]json.RawMessage{
		permitID: partialIDPolicy("permit", "when", `{"Value":true}`),
		forbidID: partialIDPolicy("forbid", "unless", `{".":{"left":{"Var":"context"},"attr":"mfa"}}`),
		errorID:  partialIDPolicy("permit", "when", `{"==":{"left":{"+":{"left":{"Value":9223372036854775807},"right":{"Value":1}}},"right":{"Value":0}}}`),
	})
	a, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	partial, err := a.PartialAuthorize(ctx, partialRequest())
	if err != nil || partial.Decision != cedar.Undecided {
		t.Fatalf("partial: %+v %v", partial, err)
	}
	ids := make([]string, 0, len(partial.Residuals))
	for _, p := range partial.Residuals {
		ids = append(ids, p.PolicyID)
	}
	if !slices.Equal(ids, []string{errorID, forbidID, permitID}) {
		t.Errorf("residual IDs = %q, want original JSON keys %q", ids, []string{errorID, forbidID, permitID})
	}
	for _, mfa := range []bool{true, false} {
		concrete := simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(mfa)}))
		wantReason, wantDecision, wantPartialDecision := permitID, cedar.Allow, cedar.PartialAllow
		if !mfa {
			wantReason, wantDecision, wantPartialDecision = forbidID, cedar.Deny, cedar.PartialDeny
		}
		known := partialRequest()
		known.Context = &concrete.Context
		decided, err := a.PartialAuthorize(ctx, known)
		if err != nil || decided.Decision != wantPartialDecision || !slices.Equal(decided.Reasons, []string{wantReason}) {
			t.Errorf("known MFA %v: decision=%v reasons=%q error=%v, want raw %q", mfa, decided.Decision, decided.Reasons, err, wantReason)
		}
		for _, authorize := range []struct {
			name string
			call func(context.Context, cedar.Request) (cedar.Response, error)
		}{{"reauthorize", partial.Reauthorize}, {"authorize", a.Authorize}} {
			response, err := authorize.call(ctx, concrete)
			if err != nil || response.Decision != wantDecision || !slices.Equal(response.Reasons, []string{wantReason}) ||
				len(response.Errors) != 1 || response.Errors[0].PolicyID != errorID || response.Errors[0].Message == "" {
				t.Errorf("%s MFA %v: %+v %v; want reason %q and error ID %q", authorize.name, mfa, response, err, wantReason, errorID)
			}
		}
	}

	t.Run("validation", func(t *testing.T) {
		const invalidID, warningID = "invalid" + suffix, "warning" + suffix
		result, err := testRuntime(t).Validate(ctx, schema, partialIDPolicies(t, map[string]json.RawMessage{
			invalidID: partialIDPolicy("permit", "when", `{".":{"left":{"Var":"principal"},"attr":"missing"}}`),
			warningID: partialIDPolicy("permit", "when", `{"Value":false}`),
		}))
		if err != nil || result.Passed || len(result.Errors) == 0 || len(result.Warnings) == 0 {
			t.Fatalf("validation: %+v %v", result, err)
		}
		for _, diagnostic := range result.Errors {
			if diagnostic.PolicyID != invalidID {
				t.Errorf("validation error ID %q, want raw %q", diagnostic.PolicyID, invalidID)
			}
		}
		for _, diagnostic := range result.Warnings {
			if diagnostic.PolicyID != warningID {
				t.Errorf("validation warning ID %q, want raw %q", diagnostic.PolicyID, warningID)
			}
		}
	})
}
