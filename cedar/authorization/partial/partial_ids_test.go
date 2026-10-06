package partial_test

import (
	context "context"
	json "encoding/json"
	authorization "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
	cedarpartial "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/partial"
	cedarrequest "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
	fault "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/fault"
	partialfixture "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/partial"
	policysupport "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/policy"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	slices "slices"
	testing "testing"
)

func TestPartialRawPolicyIDs(t *testing.T) {
	ctx := context.Background()
	schema := cedarschema.SchemaFromCedar(partialfixture.PartialSchema)
	const suffix = "\"\n\\\x00"
	const permitID, forbidID, errorID = "permit" + suffix, "forbid" + suffix, "error" + suffix
	policies := policysupport.PartialIDPolicies(t, map[string]json.RawMessage{
		permitID: policysupport.PartialIDPolicy("permit", "when", `{"Value":true}`),
		forbidID: policysupport.PartialIDPolicy("forbid", "unless", `{".":{"left":{"Var":"context"},"attr":"mfa"}}`),
		errorID:  policysupport.PartialIDPolicy("permit", "when", `{"==":{"left":{"+":{"left":{"Value":9223372036854775807},"right":{"Value":1}}},"right":{"Value":0}}}`),
	})
	a, err := testruntime.New(t).NewAuthorizer(ctx, authorization.Config{Schema: &schema, Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	partial, err := a.Partial().PartialAuthorize(ctx, partialfixture.PartialRequest())
	if err != nil || partial.Decision != cedarpartial.Undecided {
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
		concrete := fault.SimpleRequest(cedarrequest.NewContext(cedarvalue.Record{"mfa": cedarvalue.Bool(mfa)}))
		wantReason, wantDecision, wantPartialDecision := permitID, cedarrequest.Allow, cedarpartial.PartialAllow
		if !mfa {
			wantReason, wantDecision, wantPartialDecision = forbidID, cedarrequest.Deny, cedarpartial.PartialDeny
		}
		known := partialfixture.PartialRequest()
		known.Context = &concrete.Context
		decided, err := a.Partial().PartialAuthorize(ctx, known)
		if err != nil || decided.Decision != wantPartialDecision || !slices.Equal(decided.Reasons, []string{wantReason}) {
			t.Errorf("known MFA %v: decision=%v reasons=%q error=%v, want raw %q", mfa, decided.Decision, decided.Reasons, err, wantReason)
		}
		for _, authorize := range []struct {
			name string
			call func(context.Context, cedarrequest.Request) (cedarrequest.Response, error)
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
		result, err := testruntime.New(t).Validation().Validate(ctx, schema, policysupport.PartialIDPolicies(t, map[string]json.RawMessage{
			invalidID: policysupport.PartialIDPolicy("permit", "when", `{".":{"left":{"Var":"principal"},"attr":"missing"}}`),
			warningID: policysupport.PartialIDPolicy("permit", "when", `{"Value":false}`),
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
