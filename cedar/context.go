package cedar

import (
	"bytes"
)

// Context holds the context record of a request, either as a Go [Record] or
// as Cedar JSON. The zero value is the empty record.
type Context struct {
	record Record
	raw    []byte
	isJSON bool
}

// NewContext returns a context built from a record.
func NewContext(r Record) Context { return Context{record: r} }

// ContextFromJSON returns a context in Cedar's JSON value format. It must be
// a JSON object.
func ContextFromJSON(data []byte) Context { return Context{raw: bytes.Clone(data), isJSON: true} }

// MarshalJSON implements [json.Marshaler] with Cedar's JSON value format.
func (c Context) MarshalJSON() ([]byte, error) {
	if c.isJSON {
		return c.raw, nil
	}
	return c.record.MarshalJSON()
}
