package expression_test

import (
	context "context"
	errors "errors"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	expression "github.com/ChrisMckerracher/cedar-go-wasm/cedar/expression"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	reflect "reflect"
	testing "testing"
)

func TestExpressionEvaluationVariants(t *testing.T) {
	rt := testruntime.New(t)
	principal := entityuid.NewEntityUID("User", "雪")
	env := expression.ExpressionEnv{Principal: &principal, Context: cedarrequest.NewContext(cedarvalue.Record{"number": cedarvalue.Long(9007199254740993)}), Entities: cedarentity.NewEntities(cedarentity.Entity{UID: principal, Attrs: cedarvalue.Record{"age": cedarvalue.Long(9007199254740993)}})}
	cases := map[string]cedarvalue.EvalResult{
		"true": cedarvalue.Bool(true), "false": cedarvalue.Bool(false),
		"principal.age + 1":    cedarvalue.Long(9007199254740994),
		"context.number":       cedarvalue.Long(9007199254740993),
		"9223372036854775807":  cedarvalue.Long(9223372036854775807),
		"-9223372036854775808": cedarvalue.Long(-9223372036854775808),
		`"雪😀"`:                 cedarvalue.String("雪😀"), "principal": cedarvalue.EntityRef(principal),
		`[1, 1, 2]`:                 cedarvalue.EvalSet{cedarvalue.Long(1), cedarvalue.Long(2)},
		`{a: 1, b: [true], c: "雪"}`: cedarvalue.EvalRecord{"a": cedarvalue.Long(1), "b": cedarvalue.EvalSet{cedarvalue.Bool(true)}, "c": cedarvalue.String("雪")},
		"[]":                        cedarvalue.EvalSet{}, "{}": cedarvalue.EvalRecord{},
		`decimal("1.25")`: cedarvalue.ExtensionValue(`decimal("1.25")`),
		`ip("127.0.0.1")`: cedarvalue.ExtensionValue(`ip("127.0.0.1")`),
		`duration("1s")`:  cedarvalue.ExtensionValue(`duration("1s")`),
	}
	for source, want := range cases {
		t.Run(source, func(t *testing.T) {
			expr, err := rt.Expressions().ParseExpression(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := rt.Expressions().EvalExpression(context.Background(), expr, env)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v (%T), %v; want %#v", got, got, err, want)
			}
		})
	}
}

func TestExpressionErrors(t *testing.T) {
	rt := testruntime.New(t)
	for _, source := range []string{"1 +", ""} {
		_, err := rt.Expressions().ParseExpression(context.Background(), source)
		var e *diagnostic.Error
		if !errors.As(err, &e) || e.Kind != diagnostic.KindExpression {
			t.Fatalf("parse %q: %v", source, err)
		}
	}
	for _, source := range []string{"principal", "1 + 2", "if true then 1 else 2"} {
		_, err := rt.Expressions().ParseRestrictedExpression(context.Background(), source)
		var e *diagnostic.Error
		if !errors.As(err, &e) || e.Kind != diagnostic.KindExpression {
			t.Fatalf("restricted parse %q: %v", source, err)
		}
	}
	for _, source := range []string{"principal.age", "context.missing", "9223372036854775807 + 1", `decimal("bad")`, `principal == ?principal`} {
		expr, err := rt.Expressions().ParseExpression(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		result, err := rt.Expressions().EvalExpression(context.Background(), expr, expression.ExpressionEnv{})
		var e *diagnostic.Error
		if result != nil || !errors.As(err, &e) || e.Kind != diagnostic.KindExpression {
			t.Fatalf("evaluate %q: %#v %v", source, result, err)
		}
	}
	result, err := rt.Expressions().EvalExpression(context.Background(), expression.Expression{}, expression.ExpressionEnv{})
	if result != nil {
		t.Fatal("zero expression returned a value")
	}
	fault.RequireUTF8InputError(t, err)
	_, err = rt.Expressions().ParseExpression(context.Background(), string([]byte{0xff}))
	fault.RequireUTF8InputError(t, err)
	restricted, err := rt.Expressions().ParseRestrictedExpression(context.Background(), `{value: decimal("1.25"), numbers: [1, 2]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Expressions().EvalExpression(context.Background(), restricted.Expression(), expression.ExpressionEnv{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = rt.Expressions().EvalExpression(ctx, restricted.Expression(), expression.ExpressionEnv{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
