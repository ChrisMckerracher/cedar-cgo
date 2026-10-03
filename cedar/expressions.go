package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Expression is an immutable expression parsed by Cedar.
type Expression struct {
	text  string
	valid bool
}

func (e Expression) Text() string { return e.text }

// RestrictedExpression permits literal values and extension constructors only.
type RestrictedExpression struct{ expression Expression }

func (e RestrictedExpression) Text() string           { return e.expression.Text() }
func (e RestrictedExpression) Expression() Expression { return e.expression }

// EvalResult preserves Cedar's seven evaluation result variants.
type EvalResult interface{ cedarEvalResult() }

func (Bool) cedarEvalResult()      {}
func (Long) cedarEvalResult()      {}
func (String) cedarEvalResult()    {}
func (EntityUID) cedarEvalResult() {}

// EvalSet contains unique values in Cedar's deterministic result order.
type EvalSet []EvalResult

func (EvalSet) cedarEvalResult() {}

// EvalRecord maps attribute names to evaluated values.
type EvalRecord map[string]EvalResult

func (EvalRecord) cedarEvalResult() {}

// ExtensionValue retains Cedar's canonical restricted expression, such as decimal("1.0").
type ExtensionValue string

func (ExtensionValue) cedarEvalResult() {}

// ExpressionEnv supplies expression variables and entities. Nil UIDs are unknown.
type ExpressionEnv struct {
	Principal *EntityUID
	Action    *EntityUID
	Resource  *EntityUID
	Context   Context
	Entities  Entities
}

type expressionEnvWire struct {
	Principal *wire.UID `json:"principal"`
	Action    *wire.UID `json:"action"`
	Resource  *wire.UID `json:"resource"`
	Context   Context   `json:"context"`
	Entities  Entities  `json:"entities"`
}

type expressionInput struct {
	Operation   string             `json:"operation"`
	Expression  wire.Source        `json:"expression"`
	Restricted  bool               `json:"restricted"`
	Environment *expressionEnvWire `json:"environment"`
}

type expressionOutput struct {
	Expression *string         `json:"expression"`
	Result     json.RawMessage `json:"result"`
	Error      *wire.Error     `json:"error"`
}

func (rt *Runtime) expressionCall(ctx context.Context, input expressionInput) (expressionOutput, error) {
	in, err := json.Marshal(input)
	if err != nil {
		return expressionOutput{}, &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return expressionOutput{}, limitError("expression input", len(in), rt.maxSourceBytes)
	}
	out, err := rt.callOnce(ctx, "cgw_expressions", in)
	if err != nil {
		return expressionOutput{}, err
	}
	var result expressionOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return expressionOutput{}, faultError(fmt.Errorf("decode expression response: %w", err))
	}
	if result.Error != nil {
		return expressionOutput{}, moduleError(result.Error)
	}
	return result, nil
}

func (rt *Runtime) parseExpression(ctx context.Context, text string, restricted bool) (Expression, error) {
	result, err := rt.expressionCall(ctx, expressionInput{Operation: "parse", Expression: wire.Source{Format: "cedar", Text: text}, Restricted: restricted})
	if err != nil {
		return Expression{}, err
	}
	if result.Expression == nil || *result.Expression == "" {
		return Expression{}, faultError(fmt.Errorf("expression response has no expression"))
	}
	return Expression{text: *result.Expression, valid: true}, nil
}

func (rt *Runtime) ParseExpression(ctx context.Context, text string) (Expression, error) {
	return rt.parseExpression(ctx, text, false)
}
func (rt *Runtime) ParseRestrictedExpression(ctx context.Context, text string) (RestrictedExpression, error) {
	expr, err := rt.parseExpression(ctx, text, true)
	return RestrictedExpression{expression: expr}, err
}

// EvalExpression evaluates with native Cedar semantics and exact signed 64-bit integers.
// The caller's context bounds time; runtime source, memory, and response limits apply.
func (rt *Runtime) EvalExpression(ctx context.Context, expr Expression, env ExpressionEnv) (EvalResult, error) {
	if !expr.valid {
		return nil, &Error{Kind: KindInput, Message: "zero Expression is invalid"}
	}
	result, err := rt.expressionCall(ctx, expressionInput{Operation: "evaluate", Expression: wire.Source{Format: "cedar", Text: expr.text}, Environment: &expressionEnvWire{policyUID(env.Principal), policyUID(env.Action), policyUID(env.Resource), env.Context, env.Entities}})
	if err != nil {
		return nil, err
	}
	value, err := decodeEvalResult(result.Result)
	if err != nil {
		return nil, faultError(fmt.Errorf("decode evaluation result: %w", err))
	}
	return value, nil
}

func decodeEvalResult(data []byte) (EvalResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("evaluation result must be an object")
	}
	if !decoder.More() {
		return nil, fmt.Errorf("missing evaluation variant")
	}
	name, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	kind, ok := name.(string)
	if !ok {
		return nil, fmt.Errorf("invalid evaluation variant")
	}
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("evaluation result must have one variant")
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid evaluation result end")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing evaluation result data")
	}

	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, fmt.Errorf("null evaluation result")
	}
	switch kind {
	case "bool":
		var v bool
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return Bool(v), nil
	case "long":
		var v int64
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return Long(v), nil
	case "string":
		var v string
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return String(v), nil
	case "entity_uid":
		var v struct {
			Type *string
			ID   *string
		}
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		if v.Type == nil || v.ID == nil || *v.Type == "" {
			return nil, fmt.Errorf("entity result is missing identity fields")
		}
		return EntityUID{Type: *v.Type, ID: *v.ID}, nil
	case "extension":
		var v string
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		if v == "" {
			return nil, fmt.Errorf("empty extension value")
		}
		return ExtensionValue(v), nil
	case "set":
		var members []json.RawMessage
		if err := json.Unmarshal(value, &members); err != nil {
			return nil, err
		}
		result := make(EvalSet, len(members))
		for i, member := range members {
			var err error
			result[i], err = decodeEvalResult(member)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case "record":
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(value, &attrs); err != nil {
			return nil, err
		}
		result := make(EvalRecord, len(attrs))
		for name, attr := range attrs {
			v, err := decodeEvalResult(attr)
			if err != nil {
				return nil, err
			}
			result[name] = v
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown evaluation variant %q", kind)
	}
}
