package format

import (
	context "context"
	json "encoding/json"
	fmt "fmt"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	utf8 "unicode/utf8"
)

type FormatConfig struct {
	LineWidth      uint32 `json:"line_width"`
	IndentWidth    int32  `json:"indent_width"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

// FormatOption configures the experimental [Client.FormatPolicies] operation.
type FormatOption func(*FormatConfig)

// WithFormatLineWidth sets the upstream target line width (default 80).
// Zero is supported; indivisible tokens and comments can exceed the target.
func WithFormatLineWidth(width uint32) FormatOption {
	return func(c *FormatConfig) { c.LineWidth = width }
}

// WithFormatIndentWidth sets upstream nesting indentation (default 2).
// Zero and negative indentation are passed through to the upstream formatter.
func WithFormatIndentWidth(width int32) FormatOption {
	return func(c *FormatConfig) { c.IndentWidth = width }
}

// WithFormatMaxOutputBytes caps the UTF-8 output before JSON encoding.
// It must be positive and no greater than [DefaultMaxResponseBytes], the default.
func WithFormatMaxOutputBytes(n int) FormatOption {
	return func(c *FormatConfig) { c.MaxOutputBytes = n }
}

type FormatInput struct {
	Text string `json:"text"`
	FormatConfig
}

type FormatOutput struct {
	Formatted *string     `json:"formatted"`
	Error     *wire.Error `json:"error"`
}

// FormatPolicies formats Cedar policy/template text with the pinned Rust formatter.
// Experimental: the Go API may change before v1. The caller's context bounds execution.
func (rt *Client) FormatPolicies(ctx context.Context, TextValue string, opts ...FormatOption) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", diagnostic.FaultError(err)
	}
	cfg := FormatConfig{LineWidth: 80, IndentWidth: 2, MaxOutputBytes: execution.DefaultMaxResponseBytes}
	for _, opt := range opts {
		if opt == nil {
			return "", &diagnostic.Error{Kind: diagnostic.KindInput, Message: "nil format option"}
		}
		opt(&cfg)
	}
	if cfg.MaxOutputBytes <= 0 || cfg.MaxOutputBytes > execution.DefaultMaxResponseBytes {
		return "", &diagnostic.Error{Kind: diagnostic.KindInput, Message: fmt.Sprintf("format max output bytes must be between 1 and %d", execution.DefaultMaxResponseBytes)}
	}
	if len(TextValue) > rt.runtime.MaxSourceBytes {
		return "", diagnostic.LimitError("format source", len(TextValue), rt.runtime.MaxSourceBytes)
	}
	// encoding/json replaces invalid UTF-8, which would silently change the source.
	if !utf8.ValidString(TextValue) {
		return "", &diagnostic.Error{Kind: diagnostic.KindInput, Message: "format source is not valid UTF-8"}
	}
	in, err := execution.Encode(FormatInput{Text: TextValue, FormatConfig: cfg}, "format input", rt.runtime.MaxSourceBytes)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", diagnostic.FaultError(err)
	}
	out, err := rt.runtime.CallOnce(ctx, "cgw_format", in)
	if err != nil {
		return "", err
	}
	return DecodeFormatOutput(out, cfg.MaxOutputBytes)
}

func DecodeFormatOutput(out []byte, maxOutput int) (string, error) {
	var resp FormatOutput
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", diagnostic.FaultError(fmt.Errorf("decode format response: %w", err))
	}
	if (resp.Formatted == nil) == (resp.Error == nil) {
		return "", diagnostic.FaultError(fmt.Errorf("format response must contain either formatted text or an error"))
	}
	if resp.Error != nil {
		if resp.Error.Kind == string(diagnostic.KindLimit) {
			return "", &diagnostic.Error{Kind: diagnostic.KindLimit, Message: resp.Error.Message}
		}
		return "", diagnostic.ModuleError(resp.Error)
	}
	if len(*resp.Formatted) > maxOutput {
		return "", diagnostic.FaultError(fmt.Errorf("format response exceeds the requested output limit"))
	}
	return *resp.Formatted, nil
}
