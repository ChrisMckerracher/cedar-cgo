package expression

import (
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	fmt "fmt"
	request "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	policy "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Expression is an immutable expression parsed by Cedar.
type Expression struct {
	text  string
	valid bool
}

func (e Expression) Text() string { return e.text }

// RestrictedExpression permits literal values and extension constructors only.
type RestrictedExpression struct{ expression Expression }

func (e RestrictedExpression) Text() string { return e.expression.Text() }

func (e RestrictedExpression) Expression() Expression { return e.expression }

// ExpressionEnv supplies expression variables and entities. Nil UIDs are unknown.
type ExpressionEnv struct {
	Principal *entityuid.EntityUID
	Action    *entityuid.EntityUID
	Resource  *entityuid.EntityUID
	Context   request.Context
	Entities  entity.Entities
}

type ExpressionEnvWire struct {
	Principal *wire.UID       `json:"principal"`
	Action    *wire.UID       `json:"action"`
	Resource  *wire.UID       `json:"resource"`
	Context   request.Context `json:"context"`
	Entities  entity.Entities `json:"entities"`
}

type ExpressionInput struct {
	Operation   string             `json:"operation"`
	Expression  wire.Source        `json:"expression"`
	Restricted  bool               `json:"restricted"`
	Environment *ExpressionEnvWire `json:"environment"`
}

type ExpressionOutput struct {
	Expression *string         `json:"expression"`
	Result     json.RawMessage `json:"result"`
	Error      *wire.Error     `json:"error"`
}

func (rt *Client) expressionCall(ctx context.Context, input ExpressionInput) (ExpressionOutput, error) {
	in, err := execution.Encode(input, "expression input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return ExpressionOutput{}, err
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_expressions", in)
	if err != nil {
		return ExpressionOutput{}, err
	}
	var result ExpressionOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return ExpressionOutput{}, diagnostic.FaultError(fmt.Errorf("decode expression response: %w", err))
	}
	if result.Error != nil {
		return ExpressionOutput{}, diagnostic.ModuleError(result.Error)
	}
	return result, nil
}

func (rt *Client) parseExpression(ctx context.Context, text string, restricted bool) (Expression, error) {
	result, err := rt.expressionCall(ctx, ExpressionInput{Operation: "parse", Expression: wire.Source{Format: "cedar", Text: text}, Restricted: restricted})
	if err != nil {
		return Expression{}, err
	}
	if result.Expression == nil || *result.Expression == "" {
		return Expression{}, diagnostic.FaultError(fmt.Errorf("expression response has no expression"))
	}
	return Expression{text: *result.Expression, valid: true}, nil
}

func (rt *Client) ParseExpression(ctx context.Context, text string) (Expression, error) {
	return rt.parseExpression(ctx, text, false)
}

func (rt *Client) ParseRestrictedExpression(ctx context.Context, text string) (RestrictedExpression, error) {
	expr, err := rt.parseExpression(ctx, text, true)
	return RestrictedExpression{expression: expr}, err
}

// EvalExpression evaluates with native Cedar semantics and exact signed 64-bit integers.
// The caller's context bounds time; runtime source and response byte limits apply.
func (rt *Client) EvalExpression(ctx context.Context, expr Expression, env ExpressionEnv) (cedarvalue.EvalResult, error) {
	if !expr.valid {
		return nil, &diagnostic.Error{Kind: diagnostic.KindInput, Message: "zero Expression is invalid"}
	}
	result, err := rt.expressionCall(ctx, ExpressionInput{Operation: "evaluate", Expression: wire.Source{Format: "cedar", Text: expr.text}, Environment: &ExpressionEnvWire{policy.PolicyUID(env.Principal), policy.PolicyUID(env.Action), policy.PolicyUID(env.Resource), env.Context, env.Entities}})
	if err != nil {
		return nil, err
	}
	value, err := cedarvalue.DecodeEvalResult(result.Result)
	if err != nil {
		return nil, diagnostic.FaultError(fmt.Errorf("decode evaluation result: %w", err))
	}
	return value, nil
}
