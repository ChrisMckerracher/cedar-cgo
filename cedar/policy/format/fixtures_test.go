package format_test

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	testing "testing"
)

type FormatCase struct {
	Name        string
	Input       string
	LineWidth   uint32 `json:"line_width"`
	IndentWidth int32  `json:"indent_width"`
	Valid       bool
	Contexts    []json.RawMessage
}

type FormatExpected struct {
	Name      string
	Formatted *string
	Outcomes  []struct {
		Decision string
		Reasons  []string
		ErrorIDs []string `json:"error_ids"`
	}
}

func RequireFormatError(t testing.TB, out string, err error, kind diagnostic.ErrorKind) {
	t.Helper()
	var e *diagnostic.Error
	if out != "" || !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("format = %q, %v; want empty output and %s", out, err, kind)
	}
}
