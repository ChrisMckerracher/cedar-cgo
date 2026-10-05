package request

import (
	bytes "bytes"
	cedarvalue "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
)

// Context defaults to an empty record.
type Context struct {
	record cedarvalue.Record
	raw    []byte
	isJSON bool
}

func NewContext(r cedarvalue.Record) Context { return Context{record: r} }

// ContextFromJSON requires a JSON object using Cedar's value encoding.
func ContextFromJSON(data []byte) Context { return Context{raw: bytes.Clone(data), isJSON: true} }

func (c Context) MarshalJSON() ([]byte, error) {
	if c.isJSON {
		if err := wire.CheckUTF8(string(c.raw)); err != nil {
			return nil, err
		}
		return c.raw, nil
	}
	return c.record.MarshalJSON()
}
