package cedar

import (
	"bytes"
)

// Context defaults to an empty record.
type Context struct {
	record Record
	raw    []byte
	isJSON bool
}

func NewContext(r Record) Context { return Context{record: r} }

// ContextFromJSON requires a JSON object using Cedar's value encoding.
func ContextFromJSON(data []byte) Context { return Context{raw: bytes.Clone(data), isJSON: true} }

func (c Context) MarshalJSON() ([]byte, error) {
	if c.isJSON {
		return c.raw, nil
	}
	return c.record.MarshalJSON()
}
