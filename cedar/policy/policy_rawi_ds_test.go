package policy_test

import (
	context "context"
	json "encoding/json"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	jsonassert "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/jsonassert"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	testing "testing"
)

func TestPolicyRawIDs(t *testing.T) {
	rt := testruntime.New(t)
	ctx := context.Background()
	for _, id := range []string{"quote\"", "line\n", "slash\\", "quote\"\nslash\\雪"} {
		t.Run(id, func(t *testing.T) {
			p, err := rt.Policies().ParsePolicy(ctx, id, "permit(principal,action,resource);")
			if err != nil {
				t.Fatal(err)
			}
			if p.ID() != id {
				t.Fatalf("ID escaped: %q != %q", p.ID(), id)
			}
			rebuilt, err := rt.Policies().PolicyFromJSON(ctx, p.ID(), p.JSON())
			if err != nil {
				t.Fatal(err)
			}
			if rebuilt.ID() != id {
				t.Fatal("reconstruction changed ID")
			}
			set, err := rt.Policies().AddPolicy(ctx, cedarpolicy.PoliciesFromCedar(""), rebuilt)
			if err != nil {
				t.Fatal(err)
			}
			reread, err := rt.Policies().ParsePolicySet(ctx, set.Source())
			if err != nil {
				t.Fatal(err)
			}
			if q, ok := reread.Policy(id); !ok || q.ID() != id {
				t.Fatal("lookup lost raw ID")
			}
			removed, err := rt.Policies().RemovePolicy(ctx, reread.Source(), id)
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
	if err := json.Unmarshal(LoadPolicyFixture(t).Linked.JSON, &object); err != nil {
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
	set, err := rt.Policies().ParsePolicySet(ctx, cedarpolicy.PoliciesFromJSON(data))
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
	jsonassert.Equal(t, set.JSON(), data)
}
