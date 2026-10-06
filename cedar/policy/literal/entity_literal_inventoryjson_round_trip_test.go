package literal_test

import (
	json "encoding/json"
	entityuid "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	literal "github.com/ChrisMckerracher/cedar-cgo/cedar/policy/literal"
	reflect "reflect"
	testing "testing"
)

func TestEntityLiteralInventoryJSONRoundTrip(t *testing.T) {
	id := "quote\"\nslash\\\x00雪"
	for _, input := range []literal.EntityLiteralInventory{
		{},
		{Policies: map[string][]entityuid.EntityUID{"": nil, id: {entityuid.NewEntityUID("User", "雪\x00")}}, Templates: map[string][]entityuid.EntityUID{"template": {}}},
	} {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var output literal.EntityLiteralInventory
		if err := json.Unmarshal(data, &output); err != nil || !reflect.DeepEqual(input, output) {
			t.Fatalf("inventory identity changed: %+v %s %v", output, data, err)
		}
	}
	bad := string([]byte{0xff})
	for _, input := range []literal.EntityLiteralInventory{
		{Policies: map[string][]entityuid.EntityUID{bad: {}}},
		{Templates: map[string][]entityuid.EntityUID{bad: {}}},
		{Policies: map[string][]entityuid.EntityUID{"x": {entityuid.NewEntityUID(bad, "x")}}},
		{Templates: map[string][]entityuid.EntityUID{"x": {entityuid.NewEntityUID("User", bad)}}},
	} {
		if data, err := json.Marshal(input); err == nil || data != nil {
			t.Fatalf("invalid identity normalized: %s %v", data, err)
		}
	}
}
