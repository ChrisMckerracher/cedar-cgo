package value

import (
	json "encoding/json"
	fmt "fmt"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
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

func (v String) MarshalJSON() ([]byte, error) {
	if err := wire.CheckUTF8(string(v)); err != nil {
		return nil, err
	}
	return json.Marshal(string(v))
}

func (v Set) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	if err := CheckValues(v); err != nil {
		return nil, err
	}
	return json.Marshal([]Value(v))
}

func (v Record) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	for k, e := range v {
		if err := wire.CheckUTF8(k); err != nil {
			return nil, err
		}
		if e == nil {
			return nil, fmt.Errorf("cedar: record attribute %q is nil", k)
		}
	}
	return json.Marshal(map[string]Value(v))
}

type ExtnJSON struct {
	Extn struct {
		Fn  string `json:"fn"`
		Arg string `json:"arg"`
	} `json:"__extn"`
}

func MarshalExtn(fn, arg string) ([]byte, error) {
	if err := wire.CheckUTF8(arg); err != nil {
		return nil, err
	}
	var e ExtnJSON
	e.Extn.Fn, e.Extn.Arg = fn, arg
	return json.Marshal(e)
}

func (v Decimal) MarshalJSON() ([]byte, error) { return MarshalExtn("decimal", string(v)) }

func (v IPAddr) MarshalJSON() ([]byte, error) { return MarshalExtn("ip", string(v)) }

func (v Datetime) MarshalJSON() ([]byte, error) { return MarshalExtn("datetime", string(v)) }

func (v Duration) MarshalJSON() ([]byte, error) { return MarshalExtn("duration", string(v)) }
