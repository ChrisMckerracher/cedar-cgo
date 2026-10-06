package value

import (
	bytes "bytes"
	jsontext "encoding/json/jsontext"
	json "encoding/json/v2"
	fmt "fmt"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
)

func DecodeEvalResult(data []byte) (EvalResult, error) {
	var variants map[string]jsontext.Value
	if err := json.Unmarshal(data, &variants); err != nil {
		return nil, err
	}
	if len(variants) != 1 {
		return nil, fmt.Errorf("evaluation result must have one variant")
	}
	var kind string
	var value jsontext.Value
	for kind, value = range variants {
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
			Type *string `json:"type"`
			ID   *string `json:"id"`
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
		var members []jsontext.Value
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
		var attrs map[string]jsontext.Value
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
