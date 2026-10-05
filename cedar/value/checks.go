package value

import (
	fmt "fmt"
)

func CheckValues(vs []Value) error {
	for i, e := range vs {
		if e == nil {
			return fmt.Errorf("cedar: set element %d is nil", i)
		}
	}
	return nil
}
