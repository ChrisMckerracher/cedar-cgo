package partial

import (
	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"
	syntax "github.com/ChrisMckerracher/cedar-cgo/cedar/syntax"
	execution "github.com/ChrisMckerracher/cedar-cgo/internal/execution"
	testing "testing"
)

func TestPartialDecodeFaults(t *testing.T) {
	for _, input := range []string{
		`null`, `{}`, `[]`, `{"decision":"Allow"}`, `{"decision":"allow","reasons":[],"residuals":null}`,
		`{"decision":"allow","reasons":null,"residuals":[]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"unknown","cedar":"p"}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"other","state":"true","cedar":"p"}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"true","cedar":""}]}`,
		`{"decision":"allow","reasons":[],"residuals":[{"effect":"permit","state":"true","cedar":"p"},{"effect":"permit","state":"true","cedar":"p"}]}`,
		`{"error":{"kind":"unexpected","message":"x"}}`,
	} {
		r, err := DecodePartial([]byte(input))
		if r.Decision != Undecided || !errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("%s: %+v %v", input, r, err)
		}
	}
}

func TestResidualProjectionDecodeFaults(t *testing.T) {
	base := `{"decision":"allow","reasons":["p"],"residuals":[{"policy_id":"p","effect":"permit","state":"true","cedar":"permit(principal, action, resource);"}],"projection":{"version":1,"cedar_version":"4.13.0","policies":{"p":{"effect":"permit"}}}}`
	if _, err := DecodePartial([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(e map[string]any) { e["projection"] = nil },
		func(e map[string]any) { e["projection"].(map[string]any)["version"] = float64(2) },
		func(e map[string]any) { e["projection"].(map[string]any)["cedar_version"] = "0.0.0" },
		func(e map[string]any) { e["projection"].(map[string]any)["policies"] = nil },
		func(e map[string]any) { e["projection"].(map[string]any)["policies"] = map[string]any{} },
		func(e map[string]any) { e["projection"].(map[string]any)["policies"].(map[string]any)["p"] = nil },
		func(e map[string]any) {
			e["projection"].(map[string]any)["policies"].(map[string]any)["p"] = map[string]any{"effect": "forbid"}
		},
		func(e map[string]any) { e["residuals"].([]any)[0].(map[string]any)["state"] = "invalid" },
	} {
		var envelope map[string]any
		if err := json.Unmarshal([]byte(base), &envelope); err != nil {
			t.Fatal(err)
		}
		mutate(envelope)
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := DecodePartial(data); result.Decision != Undecided || !errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("malformed projection: %+v %v", result, err)
		}
	}
}

func TestResidualPolicyIDPresence(t *testing.T) {
	for _, id := range []string{"", "policy\"\n\\\x00"} {
		for _, field := range []string{"present", "missing", "null"} {
			residual := map[string]any{"policy_id": id, "effect": "permit", "state": "true", "cedar": "permit(principal, action, resource);"}
			if field == "missing" {
				delete(residual, "policy_id")
			} else if field == "null" {
				residual["policy_id"] = nil
			}
			body, err := json.Marshal(map[string]any{
				"decision": "allow", "reasons": []string{id}, "residuals": []any{residual},
				"projection": map[string]any{"version": 1, "cedar_version": syntax.CedarVersion, "policies": map[string]any{id: map[string]any{"effect": "permit"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodePartial(body)
			if field != "present" {
				if got.Decision != Undecided || !errors.Is(err, diagnostic.ErrFault) {
					t.Fatalf("%s policy ID accepted: %+v %v", field, got, err)
				}
				continue
			}
			if err != nil || got.Decision != PartialAllow || len(got.Residuals) != 1 || got.Residuals[0].PolicyID != id {
				t.Fatalf("explicit policy ID %q changed: %+v %v", id, got, err)
			}
		}
	}
}

func TestResidualImportGuardsBeforeGuest(t *testing.T) {
	a := &Client{session: &execution.Session{Limits: execution.Limits{MaxRequestBytes: 1}}}
	var limit *diagnostic.Error
	if _, err := a.ImportPartialResponse(context.Background(), []byte(`{}`)); !errors.As(err, &limit) || limit.Kind != diagnostic.KindLimit {
		t.Fatalf("limit: %v", err)
	}
	a.session.Limits.MaxRequestBytes = 1024
	for _, input := range [][]byte{
		{0xff}, []byte(`{}`), []byte(`{"version":2,"cedar_version":"4.13.0"}`),
		[]byte(`{"version":1,"cedar_version":"0.0.0"}`),
	} {
		var ce *diagnostic.Error
		if _, err := a.ImportPartialResponse(context.Background(), input); !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("input guard: %v", err)
		}
	}
	if _, err := (PartialResponse{}).Export(); err == nil {
		t.Fatal("zero response exported")
	}
}
