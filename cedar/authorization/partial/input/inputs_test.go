package input

import (
	"encoding/json"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/value"
)

func TestUnknownAndKnownEmptyInputs(t *testing.T) {
	for _, test := range []struct {
		input any
		want  string
	}{
		{UnknownEntityUID("User"), `{"type":"User","id":null}`},
		{KnownEntityUID(uid.NewEntityUID("User", "")), `{"type":"User","id":""}`},
		{NewPartialEntities(), `[]`},
		{PartialEntity{UID: uid.NewEntityUID("User", "x")}, `{"uid":{"type":"User","id":"x"},"attrs":null,"parents":null,"tags":null}`},
		{PartialEntity{UID: uid.NewEntityUID("User", "x"), Attrs: new(value.Record{}), Parents: []uid.EntityUID{}, Tags: new(value.Record{})}, `{"uid":{"type":"User","id":"x"},"attrs":{},"parents":[],"tags":{}}`},
	} {
		data, err := json.Marshal(test.input)
		if err != nil || string(data) != test.want {
			t.Fatalf("unknown or empty input changed: %s, %v; want %s", data, err, test.want)
		}
	}
}

func TestNestedEncodingRejectsInvalidUTF8(t *testing.T) {
	bad := string([]byte{0xff})
	for _, input := range []any{
		UnknownEntityUID(bad),
		KnownEntityUID(uid.NewEntityUID("User", bad)),
		PartialEntity{UID: uid.NewEntityUID("User", bad)},
		PartialEntity{UID: uid.NewEntityUID("User", "x"), Attrs: new(value.Record{bad: value.Long(1)})},
		PartialEntity{UID: uid.NewEntityUID("User", "x"), Parents: []uid.EntityUID{uid.NewEntityUID("Group", bad)}},
	} {
		if data, err := json.Marshal(input); err == nil {
			t.Fatalf("legacy outer encoding accepted invalid nested input: %s, %v", data, err)
		}
	}
}
