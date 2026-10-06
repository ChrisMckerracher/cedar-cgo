package value

import (
	json "encoding/json/v2"
	fmt "fmt"
)

// Value uses Cedar's JSON encoding; records with only "__entity" or "__extn"
// are interpreted as entity references or extension values.
type Value interface {
	json.Marshaler
	cedarValue()
}

type Bool bool

type Long int64

type String string

// Set ignores order and duplicates when evaluated by Cedar.
type Set []Value

type Record map[string]Value

// Decimal accepts Cedar's decimal() syntax, such as "12.3456".
type Decimal string

// IPAddr accepts Cedar's ip() syntax, such as "10.0.0.0/8".
type IPAddr string

// Datetime accepts Cedar's datetime() syntax, such as "2026-10-01T12:00:00Z".
type Datetime string

// Duration accepts Cedar's duration() syntax, such as "1h30m".
type Duration string

func (Bool) cedarValue() {}

func (Long) cedarValue() {}

func (String) cedarValue() {}

func (Set) cedarValue() {}

func (Record) cedarValue() {}

func (Decimal) cedarValue() {}

func (IPAddr) cedarValue() {}

func (Datetime) cedarValue() {}

func (Duration) cedarValue() {}

func (v Bool) MarshalJSON() ([]byte, error) { return json.Marshal(bool(v)) }

func (v Long) MarshalJSON() ([]byte, error) { return json.Marshal(int64(v)) }

func (v String) MarshalJSON() ([]byte, error) { return json.Marshal(string(v)) }

func (v Set) MarshalJSON() ([]byte, error) {
	if err := CheckValues(v); err != nil {
		return nil, err
	}
	return json.Marshal([]Value(v))
}

func (v Record) MarshalJSON() ([]byte, error) {
	for k, e := range v {
		if e == nil {
			return nil, fmt.Errorf("cedar: record attribute %q is nil", k)
		}
	}
	return json.Marshal(map[string]Value(v), json.Deterministic(true))
}

type extnJSON struct {
	Extn struct {
		Fn  string `json:"fn"`
		Arg string `json:"arg"`
	} `json:"__extn"`
}

func marshalExtn(fn, arg string) ([]byte, error) {
	var e extnJSON
	e.Extn.Fn, e.Extn.Arg = fn, arg
	return json.Marshal(e)
}

func (v Decimal) MarshalJSON() ([]byte, error) { return marshalExtn("decimal", string(v)) }

func (v IPAddr) MarshalJSON() ([]byte, error) { return marshalExtn("ip", string(v)) }

func (v Datetime) MarshalJSON() ([]byte, error) { return marshalExtn("datetime", string(v)) }

func (v Duration) MarshalJSON() ([]byte, error) { return marshalExtn("duration", string(v)) }
