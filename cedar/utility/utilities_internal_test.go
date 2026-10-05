package utility

import (
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"

	bytes "bytes"
	context "context"
	json "encoding/json"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	cedarpolicy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"

	strings "strings"
	testing "testing"
)

func CanonicalUtilityJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	if data == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestUtilityNativeFixtures(t *testing.T) {
	read := func(path string, out any) {
		data, err := fixture.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
	var inputs []map[string]json.RawMessage
	var expected []struct {
		Name   string
		Output json.RawMessage
	}
	read("../testdata/parity/utilities/input.json", &inputs)
	read("../testdata/parity/utilities/expected.json", &expected)
	if len(inputs) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt, err := newRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.runtime.Close(context.Background())
	for i, input := range inputs {
		t.Run(expected[i].Name, func(t *testing.T) {
			var name string
			if err := json.Unmarshal(input["name"], &name); err != nil || name != expected[i].Name {
				t.Fatal("fixture order mismatch")
			}
			delete(input, "name")
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			result, err := rt.runtime.CallOnce(context.Background(), "cgw_utilities", data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(CanonicalUtilityJSON(t, result), CanonicalUtilityJSON(t, expected[i].Output)) {
				t.Fatalf("got %s; native result %s", result, expected[i].Output)
			}
		})
	}
}

func TestUtilityPreflight(t *testing.T) {
	ctx := context.Background()
	rt := &Client{runtime: &execution.Runtime{MaxSourceBytes: execution.DefaultMaxSourceBytes}}
	bad := string([]byte{0xff})
	uid := entityuid.NewEntityUID("User", bad)
	cases := []func() error{
		func() error { _, err := rt.ParseEntityUID(ctx, bad); return err },
		func() error { _, err := uid.CedarText(ctx, rt); return err },
		func() error { _, _, err := (cedarrequest.Context{}).Get(ctx, rt, bad); return err },
		func() error {
			_, err := cedarrequest.NewContext(cedarvalue.Record{bad: cedarvalue.Bool(true)}).Values(ctx, rt)
			return err
		},
		func() error {
			_, err := (cedarrequest.Context{}).Merge(ctx, rt, cedarrequest.NewContext(cedarvalue.Record{"a": cedarvalue.String(bad)}))
			return err
		},
		func() error {
			return (cedarrequest.Context{}).Validate(ctx, rt, cedarschema.SchemaFromCedar(bad), entityuid.NewEntityUID("Action", "view"))
		},
		func() error { return rt.ValidateScopeVariables(ctx, cedarschema.SchemaFromCedar(""), uid, uid, uid) },
		func() error { _, err := rt.ConfusableStrings(ctx, cedarpolicy.PoliciesFromCedar(bad)); return err },
	}
	for _, check := range cases {
		var ce *diagnostic.Error
		if err := check(); !errors.As(err, &ce) || ce.Kind != diagnostic.KindInput {
			t.Fatalf("invalid UTF-8 reached native execution: %v", err)
		}
	}
	rt.runtime.MaxSourceBytes = 1
	var ce *diagnostic.Error
	if _, err := rt.ParseEntityUID(ctx, strings.Repeat("a", 100)); !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatalf("source limit: %v", err)
	}
	if _, err := rt.LanguageVersion(ctx); !errors.As(err, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatalf("version envelope limit: %v", err)
	}
	for _, valid := range []*bool{nil, new(bool)} {
		if err := execution.UtilityValidationResult(execution.UtilityOutput{Valid: valid}, nil); !errors.As(err, &ce) || ce.Kind != diagnostic.KindFault {
			t.Fatalf("accepted malformed validation result: %v", err)
		}
	}
	trueValue := true
	if err := execution.UtilityValidationResult(execution.UtilityOutput{Valid: &trueValue}, nil); err != nil {
		t.Fatal(err)
	}
	if got := diagnostic.ModuleError(&wire.Error{Kind: "entity_uid", Message: "invalid UID"}); got.Kind != diagnostic.KindEntityUID {
		t.Fatal("standalone UID error became a fault")
	}
}
