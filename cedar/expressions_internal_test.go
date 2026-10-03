package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestExpressionNativeFixtures(t *testing.T) {
	var inputs []struct {
		Expression  string
		Restricted  bool
		Environment struct {
			Principal, Action, Resource *EntityUID
			Context                     json.RawMessage
			Entities                    json.RawMessage
		}
	}
	var expected []struct {
		Expression string
		Result     json.RawMessage
		ErrorKind  string `json:"error_kind"`
		Message    string
	}
	read := func(path string, target any) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatal(err)
		}
	}
	read("../testdata/parity/expressions/input.json", &inputs)
	read("../testdata/parity/expressions/expected.json", &expected)
	if len(inputs) != len(expected) {
		t.Fatal("fixture count mismatch")
	}
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	for i, input := range inputs {
		t.Run(input.Expression, func(t *testing.T) {
			var expr Expression
			var err error
			if input.Restricted {
				restricted, e := rt.ParseRestrictedExpression(context.Background(), input.Expression)
				expr, err = restricted.Expression(), e
			} else {
				expr, err = rt.ParseExpression(context.Background(), input.Expression)
			}
			var result EvalResult
			if err == nil {
				env := input.Environment
				result, err = rt.EvalExpression(context.Background(), expr, ExpressionEnv{Principal: env.Principal, Action: env.Action, Resource: env.Resource, Context: ContextFromJSON(env.Context), Entities: EntitiesFromJSON(env.Entities)})
			}
			want := expected[i]
			if want.Expression != input.Expression {
				t.Fatal("fixture order mismatch")
			}
			if want.ErrorKind != "" {
				var ce *Error
				if result != nil || !errors.As(err, &ce) || string(ce.Kind) != want.ErrorKind || ce.Message != want.Message {
					t.Fatalf("got %#v %v; native result %+v", result, err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeEvalResult(want.Result)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result, value) {
				t.Fatalf("got %#v; native result %#v", result, value)
			}
		})
	}
}

func TestMalformedEvaluationResults(t *testing.T) {
	for _, data := range []string{``, `null`, `{}`, `[]`, `{"bool":null}`, `{"long":1.5}`, `{"long":9223372036854775808}`, `{"bool":true,"long":1}`, `{"entity_uid":{}}`, `{"entity_uid":{"type":"User"}}`, `{"entity_uid":{"type":"User","id":null}}`, `{"long":1,"long":2}`, `{"extension":""}`, `{"set":[{}]}`, `{"record":{"a":null}}`, `{"unknown":true}`, "{\"string\":\"\xff\"}"} {
		if value, err := decodeEvalResult([]byte(data)); err == nil || value != nil {
			t.Fatalf("accepted malformed result %q: %#v %v", data, value, err)
		}
	}
}

func FuzzEvalResult(f *testing.F) {
	for _, data := range []string{`{"long":9007199254740993}`, `{"long":-9223372036854775808}`, `{"record":{"a":{"set":[{"bool":true}]}}}`, `null`, `{"unknown":1}`} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 4096 || strings.Count(data, "[")+strings.Count(data, "{") > 40 {
			t.Skip()
		}
		result, err := decodeEvalResult([]byte(data))
		if err != nil && result != nil {
			t.Fatal("malformed response returned a value")
		}
	})
}

func TestExpressionLimits(t *testing.T) {
	rt := &Runtime{maxSourceBytes: 80}
	_, err := rt.ParseExpression(context.Background(), strings.Repeat(" ", 500)+"true")
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatalf("source limit: %v", err)
	}
	result, err := rt.EvalExpression(context.Background(), Expression{text: "true", valid: true}, ExpressionEnv{})
	if result != nil || !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatalf("environment limit: %#v %v", result, err)
	}
}

func TestExpressionRejectsInvalidUTF8BeforeGuest(t *testing.T) {
	rt := &Runtime{maxSourceBytes: DefaultMaxSourceBytes}
	bad := string([]byte{0xff})
	uid := NewEntityUID("User", bad)
	for _, env := range []ExpressionEnv{
		{Principal: &uid}, {Action: &uid}, {Resource: &uid},
		{Context: NewContext(Record{bad: Bool(true)})},
		{Context: NewContext(Record{"a": String(bad)})},
		{Context: ContextFromJSON([]byte(`{"a":"` + bad + `"}`))},
		{Entities: NewEntities(Entity{UID: uid})},
		{Entities: EntitiesFromJSON([]byte(`[{"uid":{"type":"User","id":"` + bad + `"}}]`))},
	} {
		result, err := rt.EvalExpression(context.Background(), Expression{text: "true", valid: true}, env)
		var ce *Error
		if result != nil || !errors.As(err, &ce) || ce.Kind != KindInput {
			t.Fatalf("malformed environment: %#v %v", result, err)
		}
	}
}
