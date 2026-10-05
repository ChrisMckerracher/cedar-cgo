package native

import "fmt"

// Fault reports a native interface violation, panic, or active-call cancellation.
type Fault struct {
	Module string
	Op     string
	Err    error
}

func (f *Fault) Error() string { return fmt.Sprintf("%s native: %s: %v", f.Module, f.Op, f.Err) }
func (f *Fault) Unwrap() error { return f.Err }
