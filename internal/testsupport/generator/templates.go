package generator

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	cedar "github.com/ChrisMckerracher/cedar-cgo/cedar"
	request "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	cedarschema "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
	rapid "pgregory.net/rapid"
	reflect "reflect"
	slices "slices"
	strings "strings"
)

// propGenTemplate pairs a slot-bearing template with its textual substitution.
// The template carries no @id; the set-level ID and link ID play that role.
func PropGenTemplate() *rapid.Generator[PropTemplateCase] {
	return rapid.Custom(func(t *rapid.T) PropTemplateCase {
		id := PropGenPolicyID().Draw(t, "id")
		effect := rapid.SampledFrom([]string{"permit", "forbid"}).Draw(t, "effect")
		clauses := rapid.SliceOfN(PropGenCondition(1), 0, 6).Draw(t, "clauses")
		var conditions string
		if len(clauses) > 0 {
			kind := rapid.SampledFrom([]string{"when", "unless"}).Draw(t, "kind")
			conditions = fmt.Sprintf(" %s { %s }", kind, strings.Join(clauses, " && "))
		}
		bindings := template.SlotBindings{
			template.PrincipalSlot: PropGenDeviceUID().Draw(t, "principal"),
			template.ResourceSlot:  entityuid.NewEntityUID("Joy::Session", PropGenPolicyID().Draw(t, "resource")),
		}
		description := rapid.StringMatching(`[a-z][a-z0-9 ]{0,15}`).Draw(t, "description")
		annotation := ""
		if rapid.Bool().Draw(t, "annotate") {
			annotation = fmt.Sprintf("@description(%q) ", description)
		} else {
			description = ""
		}
		body := fmt.Sprintf(`%s(principal == ?principal, %s, resource == ?resource)%s;`,
			effect, PropGenActionScope().Draw(t, "action"), conditions)
		// EntityUID.String uses Go quoting; safe-alphabet IDs keep it valid Cedar syntax.
		concreteBody := strings.ReplaceAll(strings.ReplaceAll(body, "?principal", bindings[template.PrincipalSlot].String()),
			"?resource", bindings[template.ResourceSlot].String())
		return PropTemplateCase{
			PolicyID: id, Description: description, Bindings: bindings,
			Template: annotation + body,
			Concrete: fmt.Sprintf(`@id(%q) `, id) + concreteBody,
		}
	})
}

// propAssertStrictlyValid enforces the grammar's invariant; a failure means the
// generator drifted outside the documented TPE/slicing precondition.
func PropAssertStrictlyValid(t *rapid.T, rt *cedar.Runtime, schema cedarschema.Schema, TextValue string) {
	t.Helper()
	res, err := rt.Validation().Validate(context.Background(), schema, cedarpolicy.PoliciesFromCedar(TextValue))
	if err != nil {
		t.Fatalf("generated policies do not parse: %v\n%s", err, TextValue)
	}
	if !res.Passed {
		t.Fatalf("generated policies are not strictly valid: %v\n%s", res.Errors, TextValue)
	}
}

// propResponseEqual compares decisions, reasons, and error diagnostics exactly.
func PropResponseEqual(a, b request.Response) bool {
	return a.Decision == b.Decision && slices.Equal(a.Reasons, b.Reasons) && reflect.DeepEqual(a.Errors, b.Errors)
}

// propSameJSON mirrors policies_test.go's sameJSON for rapid's T, preserving
// exact integer tokens with json.Number.
func PropSameJSON(t *rapid.T, got, want []byte) {
	t.Helper()
	decode := func(b []byte) any {
		var v any
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.UseNumber()
		if err := decoder.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !reflect.DeepEqual(decode(got), decode(want)) {
		t.Fatalf("JSON differs\ngot:  %s\nwant: %s", got, want)
	}
}

// propNormalizedPolicyJSON adapts templates_test.go's normalization for rapid's T.
func PropNormalizedPolicyJSON(t *rapid.T, data []byte) any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if links, ok := value["templateLinks"].([]any); ok {
		slices.SortStableFunc(links, func(a, b any) int {
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			return strings.Compare(string(x), string(y))
		})
	}
	return value
}

func PropMarshalEntities(t *rapid.T, entities cedarentity.Entities) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(entities)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
