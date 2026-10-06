package generator

import (
	fmt "fmt"
	template "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/template"
	rapid "pgregory.net/rapid"
	strings "strings"
)

func PropGenActionScope() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just("action"),
		rapid.Map(rapid.SampledFrom(PropJoyActions), func(a string) string { return fmt.Sprintf("action == Joy::Action::%q", a) }),
		rapid.Custom(func(t *rapid.T) string {
			chosen := rapid.SliceOfNDistinct(rapid.SampledFrom(PropJoyActions), 1, 3, func(a string) string { return a }).Draw(t, "actions")
			quoted := make([]string, len(chosen))
			for i, a := range chosen {
				quoted[i] = fmt.Sprintf("Joy::Action::%q", a)
			}
			return "action in [" + strings.Join(quoted, ", ") + "]"
		}),
	)
}

func PropGenScope(kind string, slots bool) *rapid.Generator[string] {
	if kind == "action" {
		return PropGenActionScope()
	}
	if slots {
		if kind == "principal" {
			return rapid.Just("principal == ?principal")
		}
		return rapid.Just("resource == ?resource")
	}
	if kind == "principal" {
		return rapid.OneOf(
			rapid.Just("principal"),
			rapid.Map(rapid.SampledFrom(PropJoyDevices), func(id string) string { return fmt.Sprintf("principal == Joy::Device::%q", id) }),
			rapid.Just("principal is Joy::Device"),
			rapid.Map(rapid.SampledFrom(PropJoyAcct), func(id string) string { return fmt.Sprintf("principal in Joy::Account::%q", id) }),
			rapid.Just(`principal is Joy::Device in Joy::Account::"acct1"`),
		)
	}
	return rapid.OneOf(
		rapid.Just("resource"),
		rapid.Map(rapid.SampledFrom(PropJoySess), func(id string) string { return fmt.Sprintf("resource == Joy::Session::%q", id) }),
		rapid.Just("resource is Joy::Session"),
		rapid.Map(rapid.SampledFrom(PropJoyProj), func(id string) string { return fmt.Sprintf("resource in Joy::Project::%q", id) }),
		rapid.Just(`resource is Joy::Project in Joy::Machine::"m1"`),
	)
}

// propGenPolicy draws one static Joy-schema policy with a stable ID, built only
// from expression forms the fixture suites prove strictly valid.
func PropGenPolicy(id string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		effect := rapid.SampledFrom([]string{"permit", "forbid"}).Draw(t, "effect")
		clauses := rapid.SliceOfN(PropGenCondition(1), 0, 6).Draw(t, "clauses")
		var conditions string
		if len(clauses) > 0 {
			kind := rapid.SampledFrom([]string{"when", "unless"}).Draw(t, "kind")
			conditions = fmt.Sprintf(" %s { %s }", kind, strings.Join(clauses, " && "))
		}
		annotations := fmt.Sprintf("@id(%q)", id)
		if rapid.Bool().Draw(t, "annotate") {
			note := rapid.StringMatching(`[a-z][a-z0-9 ]{0,15}`).Draw(t, "note")
			annotations += fmt.Sprintf(" @note(%q)", note)
		}
		return fmt.Sprintf(`%s %s(%s, %s, %s)%s;`,
			annotations, effect,
			PropGenScope("principal", false).Draw(t, "principal"),
			PropGenScope("action", false).Draw(t, "action"),
			PropGenScope("resource", false).Draw(t, "resource"),
			conditions)
	})
}

func PropGenPolicySet(n int) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		parts := make([]string, 0, n)
		for i := range n {
			parts = append(parts, PropGenPolicy(fmt.Sprintf("p%d", i)).Draw(t, "policy"))
		}
		return strings.Join(parts, "\n")
	})
}

type PropTemplateCase struct {
	PolicyID    string
	Description string
	Bindings    template.SlotBindings
	Template    string
	Concrete    string
}
