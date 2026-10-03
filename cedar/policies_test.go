package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type policySnapshot struct {
	JSON     json.RawMessage       `json:"json"`
	Passed   bool                  `json:"passed"`
	Errors   []cedar.PolicyMessage `json:"errors"`
	Warnings []cedar.PolicyMessage `json:"warnings"`
	Outcomes []struct {
		MFA      bool                  `json:"mfa"`
		Decision string                `json:"decision"`
		Reasons  []string              `json:"reasons"`
		Errors   []cedar.PolicyMessage `json:"errors"`
	} `json:"outcomes"`
}

type policyFixture struct {
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
		Result  policySnapshot
	} `json:"edits"`
	Linked struct {
		JSON                json.RawMessage
		RemoveError         string `json:"remove_error"`
		TemplateRemoveError string `json:"template_remove_error"`
		Result              policySnapshot
	} `json:"linked"`
	Constructed struct {
		Syntax cedar.PolicySyntax
		JSON   json.RawMessage
		Result policySnapshot
	} `json:"constructed"`
}

func loadPolicyFixture(t testing.TB) policyFixture {
	t.Helper()
	var f policyFixture
	if err := json.Unmarshal(readFile(t, "../testdata/parity/policies/native.json"), &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != "4.13.0" {
		t.Fatalf("wrong oracle version %q", f.Version)
	}
	return f
}
func sameJSON(t testing.TB, got, want []byte) {
	t.Helper()
	var a, b any
	// UseNumber preserves all signed 64-bit Cedar integers.
	for _, x := range []struct {
		b []byte
		v *any
	}{{got, &a}, {want, &b}} {
		d := json.NewDecoder(bytes.NewReader(x.b))
		d.UseNumber()
		if err := d.Decode(x.v); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON differs\ngot: %s\nwant: %s", got, want)
	}
}
func policyErrorMatches(t testing.TB, err error, want *string) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var e *cedar.Error
	if !errors.As(err, &e) || e.Kind != cedar.KindPolicies || e.Message != *want {
		t.Fatalf("got %v; want policies error %q", err, *want)
	}
}
func checkPolicySnapshot(t *testing.T, rt *cedar.Runtime, schema string, set cedar.ParsedPolicySet, want policySnapshot) {
	t.Helper()
	ctx := context.Background()
	sameJSON(t, set.JSON(), want.JSON)
	validation, err := rt.Validate(ctx, cedar.SchemaFromCedar(schema), set.Source())
	if err != nil {
		t.Fatal(err)
	}
	sortMessages := func(m []cedar.PolicyMessage) {
		slices.SortFunc(m, func(a, b cedar.PolicyMessage) int {
			if a.PolicyID != b.PolicyID {
				return strings.Compare(a.PolicyID, b.PolicyID)
			}
			return strings.Compare(a.Message, b.Message)
		})
	}
	sortMessages(validation.Errors)
	sortMessages(want.Errors)
	sortMessages(validation.Warnings)
	sortMessages(want.Warnings)
	if validation.Passed != want.Passed || !slices.Equal(validation.Errors, want.Errors) || !slices.Equal(validation.Warnings, want.Warnings) {
		t.Fatalf("validation differs: %+v vs %+v", validation, want)
	}
	a, err := rt.NewAuthorizer(ctx, cedar.Config{Policies: set.Source(), Entities: cedar.NewEntities(cedar.Entity{UID: cedar.NewEntityUID("Photo", "p"), Attrs: cedar.Record{"public": cedar.Bool(true)}})})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, o := range want.Outcomes {
		response, err := a.Authorize(ctx, cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.NewEntityUID("Photo", "p"), Context: cedar.NewContext(cedar.Record{"mfa": cedar.Bool(o.MFA)})})
		if err != nil {
			t.Fatal(err)
		}
		sortMessages(response.Errors)
		sortMessages(o.Errors)
		if response.Decision.String() != o.Decision || !slices.Equal(response.Reasons, o.Reasons) || !slices.Equal(response.Errors, o.Errors) {
			t.Fatalf("authorization differs: %+v vs %+v", response, o)
		}
	}
}

func TestPoliciesNativeParity(t *testing.T) {
	f := loadPolicyFixture(t)
	rt := testRuntime(t)
	ctx := context.Background()
	t.Run("native-cedar-rendering", func(t *testing.T) {
		set, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(f.Rendering.Source))
		if err != nil {
			t.Fatal(err)
		}
		text, err := set.Cedar()
		if err != nil {
			t.Fatal(err)
		}
		if text != f.Rendering.Cedar {
			t.Fatalf("Cedar differs: %q vs %q", text, f.Rendering.Cedar)
		}
	})

	for _, tc := range f.Parses {
		t.Run("parse/"+tc.ID, func(t *testing.T) {
			p, err := rt.ParsePolicy(ctx, tc.ID, tc.Source)
			policyErrorMatches(t, err, tc.Error)
			if err != nil {
				return
			}
			if p.ID() != tc.ID {
				t.Fatalf("ID %q != %q", p.ID(), tc.ID)
			}
			sameJSON(t, p.JSON(), tc.JSON)
			q, err := rt.PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, q.JSON(), p.JSON())
			syntax, err := p.Syntax()
			if err != nil {
				t.Fatal(err)
			}
			q, err = rt.PolicyFromSyntax(ctx, syntax)
			if err != nil {
				t.Fatal(err)
			}
			if q.ID() != p.ID() {
				t.Fatal("PST lost ID")
			}
			sameJSON(t, q.JSON(), tc.PSTJSON)
			// PST normalizes valueless/empty annotations; compare its own stable projection.
			syntax2, err := q.Syntax()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(syntax)
			c, _ := json.Marshal(syntax2)
			sameJSON(t, b, c)
			cedarText, err := q.Cedar()
			if err != nil {
				t.Fatal(err)
			}
			if cedarText != tc.PSTCedar {
				t.Fatalf("PST Cedar differs: %q vs %q", cedarText, tc.PSTCedar)
			}
			round, err := rt.ParsePolicy(ctx, p.ID(), cedarText)
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, round.JSON(), tc.RenderedJSON)
		})
	}
	for _, tc := range f.Edits {
		t.Run(tc.Name, func(t *testing.T) {
			base := cedar.PoliciesFromJSON(tc.Base)
			var set cedar.ParsedPolicySet
			var err error
			switch {
			case tc.Add != nil:
				p, e := rt.PolicyFromJSON(ctx, tc.Add.ID, tc.Add.JSON)
				if e != nil {
					t.Fatal(e)
				}
				set, err = rt.AddPolicy(ctx, base, p)
			case tc.Remove != nil:
				set, err = rt.RemovePolicy(ctx, base, *tc.Remove)
			default:
				var renames map[string]string
				set, renames, err = rt.MergePolicySets(ctx, base, cedar.PoliciesFromJSON(tc.Other), tc.Rename)
				if err == nil && !reflect.DeepEqual(renames, tc.Renames) {
					t.Fatalf("renames %v != %v", renames, tc.Renames)
				}
			}
			policyErrorMatches(t, err, tc.Error)
			if err != nil {
				set, err = rt.ParsePolicySet(ctx, base)
				if err != nil {
					t.Fatal(err)
				}
			}
			checkPolicySnapshot(t, rt, f.Schema, set, tc.Result)
			if base.Text() != string(tc.Base) {
				t.Fatal("input mutated")
			}
			again, err := rt.ParsePolicySet(ctx, set.Source())
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, again.JSON(), set.JSON())
		})
	}
	t.Run("pst-construction", func(t *testing.T) {
		p, err := rt.PolicyFromSyntax(ctx, f.Constructed.Syntax)
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, p.JSON(), f.Constructed.JSON)
		set, err := rt.AddPolicy(ctx, cedar.ParsedPolicySet{}.Source(), p)
		if err != nil {
			t.Fatal(err)
		}
		checkPolicySnapshot(t, rt, f.Schema, set, f.Constructed.Result)
	})
	t.Run("preserve-links", func(t *testing.T) {
		set, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON(f.Linked.JSON))
		if err != nil {
			t.Fatal(err)
		}
		checkPolicySnapshot(t, rt, f.Schema, set, f.Linked.Result)
		p, ok := set.Policy("instance")
		if !ok || p.IsStatic() {
			t.Fatal("lost linked instance")
		}
		if id, ok := p.TemplateID(); !ok || id != "template" {
			t.Fatal("lost template ID")
		}
		if _, err := p.Cedar(); err == nil {
			t.Fatal("rendered linked policy")
		}
		if _, err := p.Syntax(); err == nil {
			t.Fatal("flattened linked policy")
		}
		if _, err := set.Cedar(); err == nil {
			t.Fatal("rendered set with links")
		}
		_, err = rt.RemovePolicy(ctx, set.Source(), "instance")
		policyErrorMatches(t, err, &f.Linked.RemoveError)
		_, err = rt.RemovePolicy(ctx, set.Source(), "template")
		policyErrorMatches(t, err, &f.Linked.TemplateRemoveError)
		extra, err := rt.ParsePolicy(ctx, "extra", "forbid(principal,action,resource);")
		if err != nil {
			t.Fatal(err)
		}
		updated, err := rt.AddPolicy(ctx, set.Source(), extra)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := rt.RemovePolicy(ctx, updated.Source(), "extra")
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, restored.JSON(), set.JSON())
	})
}

func TestPolicyInspectionAndIsolation(t *testing.T) {
	ctx := context.Background()
	rt := testRuntime(t)
	p, err := rt.ParsePolicy(ctx, "my-id", `@note("owner") @empty permit(principal is NS::User in NS::Group::"admins", action in [Action::"view", Action::"edit"], resource == Photo::"one") when { 9223372036854775807 == 9223372036854775807 } unless { false };`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Effect() != cedar.Permit || !p.HasNonScopeConstraint() || !p.IsStatic() {
		t.Fatal("incorrect metadata")
	}
	if v, ok := p.Annotation("empty"); !ok || v != "" {
		t.Fatal("lost empty annotation")
	}
	if _, ok := p.Annotation("missing"); ok {
		t.Fatal("unexpected annotation")
	}
	principal := p.PrincipalConstraint()
	if principal.Kind != cedar.ConstraintIsIn || principal.EntityType != "NS::User" || principal.Entity.ID != "admins" {
		t.Fatalf("bad principal %+v", principal)
	}
	principal.Entity.ID = "changed"
	action := p.ActionConstraint()
	if action.Kind != cedar.ConstraintIn || len(action.Entities) != 2 {
		t.Fatalf("bad action %+v", action)
	}
	action.Entities[0].ID = "changed"
	p.Annotations()["note"] = "changed"
	data := p.JSON()
	data[0] = 'X'
	syntax, _ := p.Syntax()
	syntax.Annotations["note"] = "changed"
	syntax.Conditions[0].Body[0] = 'X'
	syntax.Principal.Entity.ID = "changed"
	if p.PrincipalConstraint().Entity.ID != "admins" || p.ActionConstraint().Entities[0].ID == "changed" {
		t.Fatal("snapshot mutated through constraints")
	}
	if v, _ := p.Annotation("note"); v != "owner" {
		t.Fatal("snapshot annotations mutated")
	}
	if !json.Valid(p.JSON()) {
		t.Fatal("snapshot JSON mutated")
	}
	if _, err := rt.PolicyFromSyntax(ctx, mustPolicySyntax(t, p)); err != nil {
		t.Fatal(err)
	}
	set, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), p)
	if err != nil {
		t.Fatal(err)
	}
	list := set.Policies()
	list[0] = cedar.ParsedPolicy{}
	if q, ok := set.Policy("my-id"); !ok || q.ID() != "my-id" {
		t.Fatal("set mutated")
	}
	text, err := set.Cedar()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(text))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rendered.Policy("policy0"); !ok {
		t.Fatal("Cedar did not assign default ID")
	}
	if _, ok := rendered.Policy("my-id"); ok {
		t.Fatal("Cedar unexpectedly retained ID")
	}
}
func mustPolicySyntax(t testing.TB, p cedar.ParsedPolicy) cedar.PolicySyntax {
	t.Helper()
	s, e := p.Syntax()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestPolicyAdversarialSyntax(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	f := loadPolicyFixture(t)
	cases := []struct {
		name string
		edit func(*cedar.PolicySyntax)
	}{
		{"invalid-effect", func(s *cedar.PolicySyntax) { s.Effect = "allow" }},
		{"invalid-type", func(s *cedar.PolicySyntax) { s.Principal.EntityType = "not a type" }},
		{"extra-constraint-field", func(s *cedar.PolicySyntax) { s.Resource.EntityType = "User" }},
		{"extra-principal-type", func(s *cedar.PolicySyntax) { s.Principal.Kind = cedar.ConstraintAny }},
		{"extra-principal-entity", func(s *cedar.PolicySyntax) {
			e := cedar.NewEntityUID("User", "a")
			s.Principal = cedar.ScopeConstraint{Kind: cedar.ConstraintAny, Entity: &e}
		}},
		{"extra-resource-entity", func(s *cedar.PolicySyntax) { e := cedar.NewEntityUID("Photo", "p"); s.Resource.Entity = &e }},
		{"extra-action-entity", func(s *cedar.PolicySyntax) { e := cedar.NewEntityUID("Action", "view"); s.Action.Entity = &e }},
		{"extra-action-set", func(s *cedar.PolicySyntax) { s.Action.Entities = []cedar.EntityUID{} }},
		{"missing-equality-entity", func(s *cedar.PolicySyntax) { s.Resource.Kind = cedar.ConstraintEq }},
		{"slot-in-clause", func(s *cedar.PolicySyntax) { s.Conditions[0].Body = json.RawMessage(`{"Slot":"?principal"}`) }},
		{"invalid-clause", func(s *cedar.PolicySyntax) { s.Conditions[0].Kind = "otherwise" }},
		{"overflow", func(s *cedar.PolicySyntax) { s.Conditions[0].Body = json.RawMessage(`{"Value":9223372036854775808}`) }},
		{"invalid-annotation", func(s *cedar.PolicySyntax) { s.Annotations["has space"] = "x" }},
		{"invalid-JSON", func(s *cedar.PolicySyntax) { s.Conditions[0].Body = json.RawMessage(`{`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s cedar.PolicySyntax
			b, _ := json.Marshal(f.Constructed.Syntax)
			if err := json.Unmarshal(b, &s); err != nil {
				t.Fatal(err)
			}
			tc.edit(&s)
			if _, err := rt.PolicyFromSyntax(ctx, s); err == nil {
				t.Fatal("invalid syntax accepted")
			} else if errors.Is(err, cedar.ErrFault) {
				t.Fatalf("invalid syntax faulted: %v", err)
			}
		})
	}
	_, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), cedar.ParsedPolicy{})
	if err == nil {
		t.Fatal("accepted zero policy")
	}
	// Duplicate object keys must reach Rust's PolicySet parser intact.
	p, err := rt.ParsePolicy(ctx, "p", "permit(principal,action,resource);")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := `{"templates":{},"staticPolicies":{"p":` + string(p.JSON()) + `,"p":` + string(p.JSON()) + `},"templateLinks":[]}`
	if _, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON([]byte(duplicate))); err == nil {
		t.Fatal("duplicate JSON IDs accepted")
	}
}

func TestPolicyCancellation(t *testing.T) {
	rt := testRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rt.ParsePolicy(ctx, "p", "permit(principal,action,resource);")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, err = rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(""))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error: %v", err)
	}
	if _, err := rt.ParsePolicy(context.Background(), "fresh", "permit(principal,action,resource);"); err != nil {
		t.Fatal("canceled operation poisoned runtime:", err)
	}
}

func TestPolicyInvalidUTF8(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	invalid := string([]byte{0xff})
	source := "permit(principal,action,resource);"
	cases := []func() error{
		func() error { _, e := rt.ParsePolicy(ctx, invalid, source); return e },
		func() error { _, e := rt.ParsePolicy(ctx, "id", source+invalid); return e },
		func() error { _, e := rt.PolicyFromJSON(ctx, invalid, []byte(`{}`)); return e },
		func() error { _, e := rt.ParsePolicySet(ctx, cedar.PoliciesFromCedar(invalid)); return e },
		func() error { _, e := rt.RemovePolicy(ctx, cedar.PoliciesFromCedar(""), invalid); return e },
		func() error {
			s := loadPolicyFixture(t).Constructed.Syntax
			s.ID = invalid
			_, e := rt.PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			s := loadPolicyFixture(t).Constructed.Syntax
			s.Conditions[0].Body = json.RawMessage(`{"Value":"` + invalid + `"}`)
			_, e := rt.PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			s := loadPolicyFixture(t).Constructed.Syntax
			s.Annotations[invalid] = "x"
			_, e := rt.PolicyFromSyntax(ctx, s)
			return e
		},
		func() error {
			_, _, e := rt.MergePolicySets(ctx, cedar.PoliciesFromCedar(source+invalid), cedar.PoliciesFromCedar(source), false)
			return e
		},
		func() error {
			other := cedar.PoliciesFromJSON([]byte(`{"staticPolicies":{"` + invalid + `":{}}}`))
			_, _, e := rt.MergePolicySets(ctx, cedar.PoliciesFromCedar(source), other, true)
			return e
		},
	}
	for i, run := range cases {
		var e *cedar.Error
		if err := run(); !errors.As(err, &e) || e.Kind != cedar.KindInput {
			t.Fatalf("case %d: got %v", i, err)
		}
	}
}

func TestPolicyRawIDs(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	for _, id := range []string{"quote\"", "line\n", "slash\\", "quote\"\nslash\\雪"} {
		t.Run(id, func(t *testing.T) {
			p, err := rt.ParsePolicy(ctx, id, "permit(principal,action,resource);")
			if err != nil {
				t.Fatal(err)
			}
			if p.ID() != id {
				t.Fatalf("ID escaped: %q != %q", p.ID(), id)
			}
			tree, err := p.Syntax()
			if err != nil {
				t.Fatal(err)
			}
			if tree.ID != id {
				t.Fatal("syntax escaped ID")
			}
			rebuilt, err := rt.PolicyFromSyntax(ctx, tree)
			if err != nil {
				t.Fatal(err)
			}
			if rebuilt.ID() != id {
				t.Fatal("reconstruction changed ID")
			}
			set, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), rebuilt)
			if err != nil {
				t.Fatal(err)
			}
			reread, err := rt.ParsePolicySet(ctx, set.Source())
			if err != nil {
				t.Fatal(err)
			}
			if q, ok := reread.Policy(id); !ok || q.ID() != id {
				t.Fatal("lookup lost raw ID")
			}
			removed, err := rt.RemovePolicy(ctx, reread.Source(), id)
			if err != nil {
				t.Fatal(err)
			}
			if len(removed.Policies()) != 0 {
				t.Fatal("remove missed raw ID")
			}
		})
	}
	rawID := "template\"\n\\雪"
	var object struct {
		Templates map[string]json.RawMessage `json:"templates"`
		Static    map[string]json.RawMessage `json:"staticPolicies"`
		Links     []struct {
			TemplateID string          `json:"templateId"`
			NewID      string          `json:"newId"`
			Values     json.RawMessage `json:"values"`
		} `json:"templateLinks"`
	}
	if err := json.Unmarshal(loadPolicyFixture(t).Linked.JSON, &object); err != nil {
		t.Fatal(err)
	}
	object.Templates[rawID] = object.Templates["template"]
	delete(object.Templates, "template")
	object.Links[0].TemplateID = rawID
	object.Links[0].NewID = rawID + "-link"
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	set, err := rt.ParsePolicySet(ctx, cedar.PoliciesFromJSON(data))
	if err != nil {
		t.Fatal(err)
	}
	linked, ok := set.Policy(rawID + "-link")
	if !ok {
		t.Fatal("linked policy ID escaped")
	}
	if got, ok := linked.TemplateID(); !ok || got != rawID {
		t.Fatalf("template ID %q != %q", got, rawID)
	}
	sameJSON(t, set.JSON(), data)
}

func TestPolicyConcurrentSnapshots(t *testing.T) {
	rt := testRuntime(t)
	ctx := context.Background()
	p, err := rt.ParsePolicy(ctx, "base", `@owner("original") permit(principal == User::"alice",action,resource);`)
	if err != nil {
		t.Fatal(err)
	}
	base, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second", "third", "fourth"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			for range 3 {
				syntax, err := p.Syntax()
				if err != nil {
					t.Fatal(err)
				}
				syntax.ID = id
				syntax.Annotations["owner"] = id
				syntax.Principal.Entity.ID = id
				edited, err := rt.PolicyFromSyntax(ctx, syntax)
				if err != nil {
					t.Fatal(err)
				}
				set, err := rt.AddPolicy(ctx, base.Source(), edited)
				if err != nil {
					t.Fatal(err)
				}
				q, ok := set.Policy(id)
				if !ok || q.PrincipalConstraint().Entity.ID != id {
					t.Fatal("concurrent edit mixed policy state")
				}
				if len(base.Policies()) != 1 || p.PrincipalConstraint().Entity.ID != "alice" {
					t.Fatal("concurrent edit mutated original")
				}
				if owner, _ := p.Annotation("owner"); owner != "original" {
					t.Fatal("concurrent edit mutated annotations")
				}
			}
		})
	}
}
