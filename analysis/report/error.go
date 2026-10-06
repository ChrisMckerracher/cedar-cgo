package report

import "fmt"

// Error records a native analysis failure.
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("analysis: %s: %s", e.Kind, e.Message) }
