package value

// EvalResult preserves Cedar's seven evaluation result variants.
type EvalResult interface{ cedarEvalResult() }

func (Bool) cedarEvalResult() {}

func (Long) cedarEvalResult() {}

func (String) cedarEvalResult() {}

// EvalSet contains unique values in Cedar's deterministic result order.
type EvalSet []EvalResult

func (EvalSet) cedarEvalResult() {}

// EvalRecord maps attribute names to evaluated values.
type EvalRecord map[string]EvalResult

func (EvalRecord) cedarEvalResult() {}

// ExtensionValue retains Cedar's canonical restricted expression, such as decimal("1.0").
type ExtensionValue string

func (ExtensionValue) cedarEvalResult() {}
