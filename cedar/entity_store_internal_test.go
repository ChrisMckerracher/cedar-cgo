package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestEntityStoreInputLimitsBeforeGuest(t *testing.T) {
	rt := &Runtime{maxSourceBytes: 1}
	_, err := rt.ParseEntityStore(context.Background(), Entities{}, nil)
	var input *Error
	if !errors.As(err, &input) || input.Kind != KindLimit {
		t.Fatalf("input limit %v", err)
	}
	_, err = rt.ParseEntityStore(context.Background(), NewEntities(Entity{UID: NewEntityUID("User", string([]byte{255}))}), nil)
	if !errors.As(err, &input) || input.Kind != KindInput {
		t.Fatalf("UTF-8 input %v", err)
	}
}

func TestEntityStoreMalformedSnapshot(t *testing.T) {
	rt := &Runtime{}
	for _, test := range []entityStoreOutput{
		{},
		{Snapshot: []byte(`{"version":2,"entities":[]}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":[]}`), Normalized: []byte(`null`)},
		{Snapshot: []byte(`{"version":1}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":null}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":{}}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":0}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":"[]"}`), Normalized: []byte(`[]`)},
		{Snapshot: []byte(`{"version":1,"entities":false}`), Normalized: []byte(`[]`)},
	} {
		if _, err := rt.decodeEntitySnapshot(test); !errors.Is(err, ErrFault) {
			t.Fatalf("malformed snapshot accepted %+v: %v", test, err)
		}
	}
	if _, err := decodeEntityRecord(map[string]json.RawMessage{"x": []byte(`{"long":9007199254740993,"string":"bad"}`)}); !errors.Is(err, ErrFault) {
		t.Fatalf("malformed value accepted %v", err)
	}
}

func TestEntityStoreEmptySnapshot(t *testing.T) {
	rt := &Runtime{}
	store, err := rt.decodeEntitySnapshot(entityStoreOutput{
		Snapshot: []byte(`{"version":1,"entities":[]}`), Normalized: []byte(`[]`),
	})
	if err != nil || store.rt != rt {
		t.Fatalf("valid empty snapshot rejected: %+v %v", store, err)
	}
}
