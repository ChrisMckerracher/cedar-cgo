package cedar_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

func TestExpressionEvaluationVariants(t *testing.T) {
	rt := testRuntime(t)
	principal := cedar.NewEntityUID("User", "雪")
	env := cedar.ExpressionEnv{Principal: &principal, Context: cedar.NewContext(cedar.Record{"number": cedar.Long(9007199254740993)}), Entities: cedar.NewEntities(cedar.Entity{UID: principal, Attrs: cedar.Record{"age": cedar.Long(9007199254740993)}})}
	cases := map[string]cedar.EvalResult{
		"true": cedar.Bool(true), "false": cedar.Bool(false),
		"principal.age + 1":    cedar.Long(9007199254740994),
		"context.number":       cedar.Long(9007199254740993),
		"9223372036854775807":  cedar.Long(9223372036854775807),
		"-9223372036854775808": cedar.Long(-9223372036854775808),
		`"雪😀"`:                 cedar.String("雪😀"), "principal": principal,
		`[1, 1, 2]`:                 cedar.EvalSet{cedar.Long(1), cedar.Long(2)},
		`{a: 1, b: [true], c: "雪"}`: cedar.EvalRecord{"a": cedar.Long(1), "b": cedar.EvalSet{cedar.Bool(true)}, "c": cedar.String("雪")},
		"[]":                        cedar.EvalSet{}, "{}": cedar.EvalRecord{},
		`decimal("1.25")`: cedar.ExtensionValue(`decimal("1.25")`),
		`ip("127.0.0.1")`: cedar.ExtensionValue(`ip("127.0.0.1")`),
		`duration("1s")`:  cedar.ExtensionValue(`duration("1s")`),
	}
	for source, want := range cases {
		t.Run(source, func(t *testing.T) {
			expr, err := rt.ParseExpression(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := rt.EvalExpression(context.Background(), expr, env)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v (%T), %v; want %#v", got, got, err, want)
			}
		})
	}
}

func TestExpressionErrors(t *testing.T) {
	rt := testRuntime(t)
	for _, source := range []string{"1 +", ""} {
		_, err := rt.ParseExpression(context.Background(), source)
		var e *cedar.Error
		if !errors.As(err, &e) || e.Kind != cedar.KindExpression {
			t.Fatalf("parse %q: %v", source, err)
		}
	}
	for _, source := range []string{"principal", "1 + 2", "if true then 1 else 2"} {
		_, err := rt.ParseRestrictedExpression(context.Background(), source)
		var e *cedar.Error
		if !errors.As(err, &e) || e.Kind != cedar.KindExpression {
			t.Fatalf("restricted parse %q: %v", source, err)
		}
	}
	for _, source := range []string{"principal.age", "context.missing", "9223372036854775807 + 1", `decimal("bad")`, `principal == ?principal`} {
		expr, err := rt.ParseExpression(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		result, err := rt.EvalExpression(context.Background(), expr, cedar.ExpressionEnv{})
		var e *cedar.Error
		if result != nil || !errors.As(err, &e) || e.Kind != cedar.KindExpression {
			t.Fatalf("evaluate %q: %#v %v", source, result, err)
		}
	}
	result, err := rt.EvalExpression(context.Background(), cedar.Expression{}, cedar.ExpressionEnv{})
	if result != nil {
		t.Fatal("zero expression returned a value")
	}
	requireUTF8InputError(t, err)
	_, err = rt.ParseExpression(context.Background(), string([]byte{0xff}))
	requireUTF8InputError(t, err)
	restricted, err := rt.ParseRestrictedExpression(context.Background(), `{value: decimal("1.25"), numbers: [1, 2]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.EvalExpression(context.Background(), restricted.Expression(), cedar.ExpressionEnv{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = rt.EvalExpression(ctx, restricted.Expression(), cedar.ExpressionEnv{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
