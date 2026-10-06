package lifetime

import "errors"

type Failure struct {
	Cause   error
	Cleanup error
}

func (f *Failure) Error() string { return errors.Join(f.Cause, f.Cleanup).Error() }

func (f *Failure) Unwrap() []error { return []error{f.Cause, f.Cleanup} }

func Cleanup(err error) error {
	if failure, ok := errors.AsType[*Failure](err); ok {
		return failure.Cleanup
	}
	return nil
}
