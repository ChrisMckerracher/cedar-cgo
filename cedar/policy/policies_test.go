package policy_test

import (
	context "context"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"

	reflect "reflect"
	testing "testing"
)

func TestPoliciesNativeParity(t *testing.T) {
	f := LoadPolicyFixture(t)
	rt := testruntime.New(t)
	ctx := context.Background()
	t.Run("native-cedar-rendering", func(t *testing.T) {
		set, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromCedar(f.Rendering.Source))
		if err != nil {
			t.Fatal(err)
		}
		TextValue, err := set.Cedar()
		if err != nil {
			t.Fatal(err)
		}
		if TextValue != f.Rendering.Cedar {
			t.Fatalf("Cedar differs: %q vs %q", TextValue, f.Rendering.Cedar)
		}
	})

	checkNativePolicyParses(t, rt, f)
	for _, tc := range f.Edits {
		t.Run(tc.Name, func(t *testing.T) {
			base := cedarpolicy.PoliciesFromJSON(tc.Base)
			var set cedarpolicy.ParsedPolicySet
			var err error
			switch {
			case tc.Add != nil:
				p, e := rt.Policies().PolicyFromJSON(ctx, tc.Add.ID, tc.Add.JSON)
				if e != nil {
					t.Fatal(e)
				}
				set, err = rt.Policies().AddPolicy(ctx, base, p)
			case tc.Remove != nil:
				set, err = rt.Policies().RemovePolicy(ctx, base, *tc.Remove)
			default:
				var renames map[string]string
				set, renames, err = rt.Policies().MergePolicySets(ctx, base, cedarpolicy.PoliciesFromJSON(tc.Other), tc.Rename)
				if err == nil && !reflect.DeepEqual(renames, tc.Renames) {
					t.Fatalf("renames %v != %v", renames, tc.Renames)
				}
			}
			PolicyErrorMatches(t, err, tc.Error)
			if err != nil {
				set, err = rt.Policies().ParsePolicySet(ctx, base)
				if err != nil {
					t.Fatal(err)
				}
			}
			CheckPolicySnapshot(t, rt, f.Schema, set, tc.Result)
			if base.Text() != string(tc.Base) {
				t.Fatal("input mutated")
			}
			again, err := rt.Policies().ParsePolicySet(ctx, set.Source())
			if err != nil {
				t.Fatal(err)
			}
			jsonassert.Equal(t, again.JSON(), set.JSON())
		})
	}
	t.Run("json-construction", func(t *testing.T) {
		p, err := rt.Policies().PolicyFromJSON(ctx, f.Constructed.Syntax.ID, f.Constructed.JSON)
		if err != nil {
			t.Fatal(err)
		}
		jsonassert.Equal(t, p.JSON(), f.Constructed.JSON)
		set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.ParsedPolicySet{}.Source(), p)
		if err != nil {
			t.Fatal(err)
		}
		CheckPolicySnapshot(t, rt, f.Schema, set, f.Constructed.Result)
	})
	t.Run("preserve-links", func(t *testing.T) {
		set, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON(f.Linked.JSON))
		if err != nil {
			t.Fatal(err)
		}
		CheckPolicySnapshot(t, rt, f.Schema, set, f.Linked.Result)
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
		if _, err := rt.Policies().AddPolicy(ctx, cedarpolicy.ParsedPolicySet{}.Source(), p); err == nil {
			t.Fatal("added linked policy as static")
		}
		if _, err := set.Cedar(); err == nil {
			t.Fatal("rendered set with links")
		}
		_, err = rt.Policies().RemovePolicy(ctx, set.Source(), "instance")
		PolicyErrorMatches(t, err, &f.Linked.RemoveError)
		_, err = rt.Policies().RemovePolicy(ctx, set.Source(), "template")
		PolicyErrorMatches(t, err, &f.Linked.TemplateRemoveError)
		extra, err := rt.Policies().ParsePolicy(ctx, "extra", "forbid(principal,action,resource);")
		if err != nil {
			t.Fatal(err)
		}
		updated, err := rt.Policies().AddPolicy(ctx, set.Source(), extra)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := rt.Policies().RemovePolicy(ctx, updated.Source(), "extra")
		if err != nil {
			t.Fatal(err)
		}
		jsonassert.Equal(t, restored.JSON(), set.JSON())
	})
}
