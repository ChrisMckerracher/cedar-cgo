package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

type formatConfig struct {
	LineWidth      uint32 `json:"line_width"`
	IndentWidth    int32  `json:"indent_width"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

// FormatOption configures the experimental [Runtime.FormatPolicies] operation.
type FormatOption func(*formatConfig)

// WithFormatLineWidth sets the upstream target line width (default 80).
// Zero is supported; indivisible tokens and comments can exceed the target.
func WithFormatLineWidth(width uint32) FormatOption {
	return func(c *formatConfig) { c.LineWidth = width }
}

// WithFormatIndentWidth sets upstream nesting indentation (default 2).
// Zero and negative indentation are passed through to the upstream formatter.
func WithFormatIndentWidth(width int32) FormatOption {
	return func(c *formatConfig) { c.IndentWidth = width }
}

// WithFormatMaxOutputBytes caps the UTF-8 output before JSON encoding.
// It must be positive and no greater than [DefaultMaxResponseBytes], the default.
func WithFormatMaxOutputBytes(n int) FormatOption {
	return func(c *formatConfig) { c.MaxOutputBytes = n }
}

type formatInput struct {
	Text string `json:"text"`
	formatConfig
}

type formatOutput struct {
	Formatted *string     `json:"formatted"`
	Error     *wire.Error `json:"error"`
}

// FormatPolicies formats Cedar policy/template text with the pinned Rust formatter.
// Experimental: the Go API may change before v1. The caller's context bounds execution.
func (rt *Runtime) FormatPolicies(ctx context.Context, text string, opts ...FormatOption) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", faultError(err)
	}
	cfg := formatConfig{LineWidth: 80, IndentWidth: 2, MaxOutputBytes: DefaultMaxResponseBytes}
	for _, opt := range opts {
		if opt == nil {
			return "", &Error{Kind: KindInput, Message: "nil format option"}
		}
		opt(&cfg)
	}
	if cfg.MaxOutputBytes <= 0 || cfg.MaxOutputBytes > DefaultMaxResponseBytes {
		return "", &Error{Kind: KindInput, Message: fmt.Sprintf("format max output bytes must be between 1 and %d", DefaultMaxResponseBytes)}
	}
	if len(text) > rt.maxSourceBytes {
		return "", limitError("format source", len(text), rt.maxSourceBytes)
	}
	// encoding/json replaces invalid UTF-8, which would silently change the source.
	if !utf8.ValidString(text) {
		return "", &Error{Kind: KindInput, Message: "format source is not valid UTF-8"}
	}
	in, err := json.Marshal(formatInput{Text: text, formatConfig: cfg})
	if err != nil {
		return "", &Error{Kind: KindInput, Message: err.Error()}
	}
	if len(in) > rt.maxSourceBytes {
		return "", limitError("format input", len(in), rt.maxSourceBytes)
	}
	if err := ctx.Err(); err != nil {
		return "", faultError(err)
	}
	out, err := rt.callOnce(ctx, "cgw_format", in)
	if err != nil {
		return "", err
	}
	return decodeFormatOutput(out, cfg.MaxOutputBytes)
}

func decodeFormatOutput(out []byte, maxOutput int) (string, error) {
	var resp formatOutput
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", faultError(fmt.Errorf("decode format response: %w", err))
	}
	if (resp.Formatted == nil) == (resp.Error == nil) {
		return "", faultError(fmt.Errorf("format response must contain either formatted text or an error"))
	}
	if resp.Error != nil {
		if resp.Error.Kind == string(KindLimit) {
			return "", &Error{Kind: KindLimit, Message: resp.Error.Message}
		}
		return "", moduleError(resp.Error)
	}
	if len(*resp.Formatted) > maxOutput {
		return "", faultError(fmt.Errorf("format response exceeds the requested output limit"))
	}
	return *resp.Formatted, nil
}
