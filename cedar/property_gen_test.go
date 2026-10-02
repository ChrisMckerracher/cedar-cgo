package cedar_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// rapid v1.3 only offers global iteration flags, so expensive properties cap
// their own wall-clock budget and no-op the remaining checks.
func propWithinBudget(start time.Time, budget time.Duration) bool {
	return time.Since(start) < budget
}

// IDs come from an escape-free alphabet so generated Cedar text needs no quoting care.
// The x-prefix namespace cannot collide with Joy fixture IDs like phone1 or s1.
var (
	propSafeID     = rapid.StringMatching(`x[a-z0-9]{0,7}`)
	propJoyActions = []string{"session.read", "session.write", "terminal.open", "file.read", "file.write"}
	propJoyDevices = []string{"phone1", "phone2", "tab1"}
	propJoySess    = []string{"s1", "s2"}
	propJoyProj    = []string{"proj0", "proj1", "proj7"}
	propJoyAcct    = []string{"acct0", "acct1", "acct9"}
)

func propGenPolicyID() *rapid.Generator[string] { return propSafeID }

func propGenDeviceUID() *rapid.Generator[cedar.EntityUID] {
	return rapid.Map(propSafeID, func(id string) cedar.EntityUID { return cedar.NewEntityUID("Joy::Device", id) })
}

var propLeafKinds = []string{"bool", "long", "string", "decimal", "ip", "datetime", "duration", "uid", "set", "record"}

// propGenValue draws Cedar-shaped JSON values with valid extension literals.
func propGenValue(depth int) *rapid.Generator[cedar.Value] {
	return rapid.Custom(func(t *rapid.T) cedar.Value {
		kind := rapid.SampledFrom(propLeafKinds).Draw(t, "kind")
		if depth > 0 && kind == "set" {
			return cedar.Set(rapid.SliceOfN(propGenValue(depth-1), 0, 3).Draw(t, "set"))
		}
		if depth > 0 && kind == "record" {
			keys := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b", "c", "d"}), 0, 3, func(k string) string { return k }).Draw(t, "keys")
			record := cedar.Record{}
			for _, k := range keys {
				record[k] = propGenValue(depth-1).Draw(t, "value")
			}
			return record
		}
		switch kind {
		case "bool":
			return cedar.Bool(rapid.Bool().Draw(t, "bool"))
		case "long":
			return cedar.Long(rapid.Int64Range(-1000, 1000).Draw(t, "long"))
		case "string":
			return cedar.String(rapid.StringN(0, 8, 32).Draw(t, "string"))
		case "decimal":
			return cedar.Decimal(rapid.SampledFrom([]string{"1.5", "-0.99"}).Draw(t, "decimal"))
		case "ip":
			return cedar.IPAddr(rapid.SampledFrom([]string{"10.1.2.3", "2001:db8::1"}).Draw(t, "ip"))
		case "datetime":
			return cedar.Datetime(rapid.SampledFrom([]string{"2026-10-01T12:00:00Z", "1999-01-02T03:04:05Z"}).Draw(t, "datetime"))
		case "duration":
			return cedar.Duration(rapid.SampledFrom([]string{"1h30m", "23h"}).Draw(t, "duration"))
		default:
			return propGenDeviceUID().Draw(t, "uid")
		}
	})
}

// propGenContext draws a record matching Joy::Ctx so schema-checked requests accept it.
func propGenContext() *rapid.Generator[cedar.Context] {
	return rapid.Custom(func(t *rapid.T) cedar.Context {
		return cedar.NewContext(cedar.Record{
			"deviceLevel": cedar.Long(int64(rapid.IntRange(0, 3).Draw(t, "deviceLevel"))),
			"platform": cedar.Record{
				"os":            cedar.String(rapid.SampledFrom([]string{"ios", "android"}).Draw(t, "os")),
				"model":         cedar.String(rapid.StringMatching(`[A-Za-z0-9,]{0,10}`).Draw(t, "model")),
				"securityLevel": cedar.Long(int64(rapid.IntRange(0, 4).Draw(t, "securityLevel"))),
			},
			"sessionId":       cedar.String(rapid.StringMatching(`s[0-9]{0,3}`).Draw(t, "sessionId")),
			"now":             cedar.Datetime(rapid.SampledFrom([]string{"2026-10-01T12:00:00Z", "2026-10-02T23:30:00Z"}).Draw(t, "now")),
			"machineAttested": cedar.Bool(rapid.Bool().Draw(t, "machineAttested")),
			"sourceIp":        cedar.IPAddr(rapid.SampledFrom([]string{"10.1.2.3", "127.0.0.1", "192.168.1.5"}).Draw(t, "sourceIp")),
		})
	})
}

// propGenRequest draws schema-valid Joy requests with concrete UIDs and a full Ctx.
func propGenRequest() *rapid.Generator[cedar.Request] {
	return rapid.Custom(func(t *rapid.T) cedar.Request {
		return cedar.Request{
			Principal: cedar.NewEntityUID("Joy::Device", propGenPolicyID().Draw(t, "device")),
			Action:    cedar.NewEntityUID("Joy::Action", rapid.SampledFrom(propJoyActions).Draw(t, "action")),
			Resource:  cedar.NewEntityUID("Joy::Session", propGenPolicyID().Draw(t, "session")),
			Context:   propGenContext().Draw(t, "context"),
		}
	})
}

// propGenExtraEntities draws standalone entities disjoint from the Joy fixtures
// with complete parent chains, safe to augment any preloaded store.
func propGenExtraEntities() *rapid.Generator[cedar.Entities] {
	return rapid.Custom(func(t *rapid.T) cedar.Entities {
		accounts := []string{"xacct0", "xacct9"}
		extras := []cedar.Entity{
			{UID: cedar.NewEntityUID("Joy::Account", accounts[0]), Attrs: cedar.Record{}},
			{UID: cedar.NewEntityUID("Joy::Account", accounts[1]), Attrs: cedar.Record{}},
		}
		// Device declares no attributes in the Joy schema, so extras carry none.
		for _, id := range rapid.SliceOfNDistinct(propGenPolicyID(), 0, 3, func(id string) string { return id }).Draw(t, "extraDevices") {
			extras = append(extras, cedar.Entity{
				UID:     cedar.NewEntityUID("Joy::Device", id),
				Attrs:   cedar.Record{},
				Parents: []cedar.EntityUID{cedar.NewEntityUID("Joy::Account", rapid.SampledFrom(accounts).Draw(t, "acct"))},
			})
		}
		return cedar.NewEntities(extras...)
	})
}

type propEntityStore struct {
	entities cedar.Entities
	entries  []json.RawMessage
	index    map[cedar.EntityUID]int
}

// lookup serves exactly the requested UIDs; re-serving across loader rounds
// would be a duplicate-entity error, and omitted UIDs must be marked missing
// or Rust re-requests them until the iteration budget is exhausted.
func (s propEntityStore) load(t *rapid.T, uids []cedar.EntityUID) cedar.EntityLoadResult {
	t.Helper()
	out := make([]json.RawMessage, 0, len(uids))
	var missing []cedar.EntityUID
	for _, uid := range uids {
		if i, ok := s.index[uid]; ok {
			out = append(out, s.entries[i])
		} else {
			missing = append(missing, uid)
		}
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return cedar.EntityLoadResult{Entities: data, Missing: missing}
}

func (s propEntityStore) raw(t *rapid.T) []byte {
	t.Helper()
	data, err := json.Marshal(s.entries)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// propGenEntityStore returns full snapshots: the Joy entities plus generated
// extras, so policies referencing either namespace resolve to whole entities.
func propGenEntityStore(joyJSON []byte) *rapid.Generator[propEntityStore] {
	return rapid.Custom(func(t *rapid.T) propEntityStore {
		var base []json.RawMessage
		if err := json.Unmarshal(joyJSON, &base); err != nil {
			t.Fatalf("joy entities fixture: %v", err)
		}
		extra, err := json.Marshal(propGenExtraEntities().Draw(t, "extras"))
		if err != nil {
			t.Fatal(err)
		}
		var appended []json.RawMessage
		if err := json.Unmarshal(extra, &appended); err != nil {
			t.Fatal(err)
		}
		entries := append(base, appended...)
		index := make(map[cedar.EntityUID]int, len(entries))
		for i, entry := range entries {
			var wire struct {
				UID struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"uid"`
			}
			if err := json.Unmarshal(entry, &wire); err != nil {
				t.Fatalf("entity entry: %v", err)
			}
			index[cedar.NewEntityUID(wire.UID.Type, wire.UID.ID)] = i
		}
		merged, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		return propEntityStore{entities: cedar.EntitiesFromJSON(merged), entries: entries, index: index}
	})
}

// propGenCondition draws strictly-valid boolean clauses over Joy::Ctx tokens;
// every form mirrors policies the fixture suites already validate.
func propGenCondition(depth int) *rapid.Generator[string] {
	atoms := []*rapid.Generator[string]{
		rapid.Map(rapid.IntRange(0, 3), func(n int) string { return fmt.Sprintf("context.deviceLevel >= %d", n) }),
		rapid.Map(rapid.IntRange(0, 3), func(n int) string { return fmt.Sprintf("context.deviceLevel < %d", n) }),
		rapid.Just("context.machineAttested"),
		rapid.Just("!context.machineAttested"),
		rapid.Map(rapid.SampledFrom([]string{"ios", "android"}), func(os string) string {
			return fmt.Sprintf("context.platform.os == %q", os)
		}),
		rapid.Map(rapid.IntRange(0, 4), func(n int) string { return fmt.Sprintf("context.platform.securityLevel < %d", n) }),
		rapid.Map(rapid.StringMatching(`s[a-z0-9]{0,4}\*?`), func(p string) string {
			return fmt.Sprintf("context.sessionId like %q", p)
		}),
		rapid.Just("context has deviceLevel"),
		rapid.Just(`context.sourceIp.isInRange(ip("10.0.0.0/8"))`),
		rapid.Just("context.sourceIp.isLoopback()"),
		rapid.Just(`context.now.toTime() >= duration("23h")`),
		rapid.Just(`decimal("1.5").lessThan(decimal("2.0"))`),
		rapid.Map(rapid.SampledFrom(propJoyDevices), func(id string) string {
			return fmt.Sprintf("principal == Joy::Device::%q", id)
		}),
		rapid.Map(rapid.SampledFrom(propJoySess), func(id string) string {
			return fmt.Sprintf("resource == Joy::Session::%q", id)
		}),
	}
	if depth <= 0 {
		return rapid.OneOf(atoms...)
	}
	combine := rapid.Custom(func(t *rapid.T) string {
		left := propGenCondition(depth-1).Draw(t, "left")
		right := propGenCondition(depth-1).Draw(t, "right")
		op := rapid.SampledFrom([]string{"&&", "||"}).Draw(t, "op")
		if rapid.Bool().Draw(t, "negate") {
			return fmt.Sprintf("!(%s %s %s)", left, op, right)
		}
		return fmt.Sprintf("(%s %s %s)", left, op, right)
	})
	return rapid.OneOf(append(atoms, combine)...)
}

func propGenActionScope() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just("action"),
		rapid.Map(rapid.SampledFrom(propJoyActions), func(a string) string { return fmt.Sprintf("action == Joy::Action::%q", a) }),
		rapid.Custom(func(t *rapid.T) string {
			chosen := rapid.SliceOfNDistinct(rapid.SampledFrom(propJoyActions), 1, 3, func(a string) string { return a }).Draw(t, "actions")
			quoted := make([]string, len(chosen))
			for i, a := range chosen {
				quoted[i] = fmt.Sprintf("Joy::Action::%q", a)
			}
			return "action in [" + strings.Join(quoted, ", ") + "]"
		}),
	)
}

func propGenScope(kind string, slots bool) *rapid.Generator[string] {
	if kind == "action" {
		return propGenActionScope()
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
			rapid.Map(rapid.SampledFrom(propJoyDevices), func(id string) string { return fmt.Sprintf("principal == Joy::Device::%q", id) }),
			rapid.Just("principal is Joy::Device"),
			rapid.Map(rapid.SampledFrom(propJoyAcct), func(id string) string { return fmt.Sprintf("principal in Joy::Account::%q", id) }),
			rapid.Just(`principal is Joy::Device in Joy::Account::"acct1"`),
		)
	}
	return rapid.OneOf(
		rapid.Just("resource"),
		rapid.Map(rapid.SampledFrom(propJoySess), func(id string) string { return fmt.Sprintf("resource == Joy::Session::%q", id) }),
		rapid.Just("resource is Joy::Session"),
		rapid.Map(rapid.SampledFrom(propJoyProj), func(id string) string { return fmt.Sprintf("resource in Joy::Project::%q", id) }),
		rapid.Just(`resource is Joy::Project in Joy::Machine::"m1"`),
	)
}

// propGenPolicy draws one static Joy-schema policy with a stable ID, built only
// from expression forms the fixture suites prove strictly valid.
func propGenPolicy(id string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		effect := rapid.SampledFrom([]string{"permit", "forbid"}).Draw(t, "effect")
		clauses := rapid.SliceOfN(propGenCondition(1), 0, 6).Draw(t, "clauses")
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
			propGenScope("principal", false).Draw(t, "principal"),
			propGenScope("action", false).Draw(t, "action"),
			propGenScope("resource", false).Draw(t, "resource"),
			conditions)
	})
}

func propGenPolicySet(n int) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		parts := make([]string, 0, n)
		for i := range n {
			parts = append(parts, propGenPolicy(fmt.Sprintf("p%d", i)).Draw(t, "policy"))
		}
		return strings.Join(parts, "\n")
	})
}

type propTemplateCase struct {
	PolicyID    string
	Description string
	Bindings    cedar.SlotBindings
	Template    string
	Concrete    string
}

// propGenTemplate pairs a slot-bearing template with its textual substitution.
// The template carries no @id; the set-level ID and link ID play that role.
func propGenTemplate() *rapid.Generator[propTemplateCase] {
	return rapid.Custom(func(t *rapid.T) propTemplateCase {
		id := propGenPolicyID().Draw(t, "id")
		effect := rapid.SampledFrom([]string{"permit", "forbid"}).Draw(t, "effect")
		clauses := rapid.SliceOfN(propGenCondition(1), 0, 6).Draw(t, "clauses")
		var conditions string
		if len(clauses) > 0 {
			kind := rapid.SampledFrom([]string{"when", "unless"}).Draw(t, "kind")
			conditions = fmt.Sprintf(" %s { %s }", kind, strings.Join(clauses, " && "))
		}
		bindings := cedar.SlotBindings{
			cedar.PrincipalSlot: propGenDeviceUID().Draw(t, "principal"),
			cedar.ResourceSlot:  cedar.NewEntityUID("Joy::Session", propGenPolicyID().Draw(t, "resource")),
		}
		description := rapid.StringMatching(`[a-z][a-z0-9 ]{0,15}`).Draw(t, "description")
		annotation := ""
		if rapid.Bool().Draw(t, "annotate") {
			annotation = fmt.Sprintf("@description(%q) ", description)
		} else {
			description = ""
		}
		body := fmt.Sprintf(`%s(principal == ?principal, %s, resource == ?resource)%s;`,
			effect, propGenActionScope().Draw(t, "action"), conditions)
		// EntityUID.String uses Go quoting; safe-alphabet IDs keep it valid Cedar syntax.
		concreteBody := strings.ReplaceAll(strings.ReplaceAll(body, "?principal", bindings[cedar.PrincipalSlot].String()),
			"?resource", bindings[cedar.ResourceSlot].String())
		return propTemplateCase{
			PolicyID: id, Description: description, Bindings: bindings,
			Template: annotation + body,
			Concrete: fmt.Sprintf(`@id(%q) `, id) + concreteBody,
		}
	})
}

// propAssertStrictlyValid enforces the grammar's invariant; a failure means the
// generator drifted outside the documented TPE/slicing precondition.
func propAssertStrictlyValid(t *rapid.T, rt *cedar.Runtime, schema cedar.Schema, text string) {
	t.Helper()
	res, err := rt.Validate(context.Background(), schema, cedar.PoliciesFromCedar(text))
	if err != nil {
		t.Fatalf("generated policies do not parse: %v\n%s", err, text)
	}
	if !res.Passed {
		t.Fatalf("generated policies are not strictly valid: %v\n%s", res.Errors, text)
	}
}

// propResponseEqual compares decisions, reasons, and error diagnostics exactly.
func propResponseEqual(a, b cedar.Response) bool {
	return a.Decision == b.Decision && slices.Equal(a.Reasons, b.Reasons) && slices.Equal(a.Errors, b.Errors)
}

// propSameJSON mirrors policies_test.go's sameJSON for rapid's T, preserving
// exact integer tokens with json.Number.
func propSameJSON(t *rapid.T, got, want []byte) {
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
func propNormalizedPolicyJSON(t *rapid.T, data []byte) any {
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

func propMarshalEntities(t *rapid.T, entities cedar.Entities) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(entities)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
