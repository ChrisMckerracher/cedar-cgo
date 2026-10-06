package value

import (
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
)

type EntityRef uid.EntityUID

func (EntityRef) cedarValue()                    {}
func (v EntityRef) MarshalJSON() ([]byte, error) { return uid.EntityUID(v).MarshalJSON() }

func (EntityRef) cedarEvalResult() {}
