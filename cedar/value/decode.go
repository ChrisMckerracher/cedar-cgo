package value

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	wire "github.com/ChrisMckerracher/cedar-go-wasm/internal/wire"
	io "io"
)

func DecodeEvalResult(data []byte) (EvalResult, error) {
	if err := wire.CheckUTF8(string(data)); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("evaluation result must be an object")
	}
	if !decoder.More() {
		return nil, fmt.Errorf("missing evaluation variant")
	}
	name, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	kind, ok := name.(string)
	if !ok {
		return nil, fmt.Errorf("invalid evaluation variant")
	}
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("evaluation result must have one variant")
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid evaluation result end")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing evaluation result data")
	}

	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, fmt.Errorf("null evaluation result")
	}
	switch kind {
	case "bool":
		var v bool
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return Bool(v), nil
	case "long":
		var v int64
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return Long(v), nil
	case "string":
		var v string
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		return String(v), nil
	case "entity_uid":
		var v struct {
			Type *string
			ID   *string
		}
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		if v.Type == nil || v.ID == nil || *v.Type == "" {
			return nil, fmt.Errorf("entity result is missing identity fields")
		}
		return EntityRef(entityuid.EntityUID{Type: *v.Type, ID: *v.ID}), nil
	case "extension":
		var v string
		if err := json.Unmarshal(value, &v); err != nil {
			return nil, err
		}
		if v == "" {
			return nil, fmt.Errorf("empty extension value")
		}
		return ExtensionValue(v), nil
	case "set":
		var members []json.RawMessage
		if err := json.Unmarshal(value, &members); err != nil {
			return nil, err
		}
		result := make(EvalSet, len(members))
		for i, member := range members {
			var err error
			result[i], err = DecodeEvalResult(member)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case "record":
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(value, &attrs); err != nil {
			return nil, err
		}
		result := make(EvalRecord, len(attrs))
		for name, attr := range attrs {
			v, err := DecodeEvalResult(attr)
			if err != nil {
				return nil, err
			}
			result[name] = v
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown evaluation variant %q", kind)
	}
}
