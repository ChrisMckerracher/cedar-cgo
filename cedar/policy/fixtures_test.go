package policy_test

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	testing "testing"
)

type PolicySnapshot struct {
	JSON     json.RawMessage            `json:"json"`
	Passed   bool                       `json:"passed"`
	Errors   []diagnostic.PolicyMessage `json:"errors"`
	Warnings []diagnostic.PolicyMessage `json:"warnings"`
	Outcomes []struct {
		MFA      bool                       `json:"mfa"`
		Decision string                     `json:"decision"`
		Reasons  []string                   `json:"reasons"`
		Errors   []diagnostic.PolicyMessage `json:"errors"`
	} `json:"outcomes"`
}

type PolicyFixture struct {
	Rendering struct {
		Source string
		Cedar  string
	} `json:"rendering"`
	Version string `json:"version"`
	Schema  string `json:"schema"`
	Parses  []struct {
		ID, Source   string
		PSTCedar     string          `json:"pst_cedar"`
		PSTJSON      json.RawMessage `json:"pst_json"`
		RenderedJSON json.RawMessage `json:"rendered_json"`
		JSON         json.RawMessage
		Error        *string
	} `json:"parses"`
	Edits []struct {
		Name string
		Base json.RawMessage
		Add  *struct {
			ID   string
			JSON json.RawMessage
		}
		Remove  *string
		Other   json.RawMessage
		Rename  bool
		Renames map[string]string
		Error   *string
		Result  PolicySnapshot
	} `json:"edits"`
	Linked struct {
		JSON                json.RawMessage
		RemoveError         string `json:"remove_error"`
		TemplateRemoveError string `json:"template_remove_error"`
		Result              PolicySnapshot
	} `json:"linked"`
	Constructed struct {
		Syntax struct{ ID string }
		JSON   json.RawMessage
		Result PolicySnapshot
	} `json:"constructed"`
}

func LoadPolicyFixture(t testing.TB) PolicyFixture {
	t.Helper()
	var f PolicyFixture
	if err := json.Unmarshal(fixture.MustReadFile(t, "../testdata/parity/policies/native.json"), &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != "4.13.0" {
		t.Fatalf("wrong oracle version %q", f.Version)
	}
	return f
}

func PolicyErrorMatches(t testing.TB, err error, want *string) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var e *diagnostic.Error
	if !errors.As(err, &e) || e.Kind != diagnostic.KindPolicies || e.Message != *want {
		t.Fatalf("got %v; want policies error %q", err, *want)
	}
}
