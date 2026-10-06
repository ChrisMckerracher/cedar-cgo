package store

import (
	entity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	execution "github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"

	context "context"
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	testing "testing"
)

func TestEntityStoreInputLimitsBeforeGuest(t *testing.T) {
	rt := &Client{runtime: &execution.Runtime{MaxSourceBytes: 1}}
	_, err := rt.ParseEntityStore(context.Background(), entity.Entities{}, nil)
	var input *diagnostic.Error
	if !errors.As(err, &input) || input.Kind != diagnostic.KindLimit {
		t.Fatalf("input limit %v", err)
	}
	_, err = rt.ParseEntityStore(context.Background(), entity.NewEntities(entity.Entity{UID: entityuid.NewEntityUID("User", string([]byte{255}))}), nil)
	if !errors.As(err, &input) || input.Kind != diagnostic.KindInput {
		t.Fatalf("UTF-8 input %v", err)
	}
}

func TestEntityStoreMalformedSnapshot(t *testing.T) {
	rt := &Client{}
	for _, test := range []storeOutput{
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
		if _, err := rt.decodeEntitySnapshot(test); !errors.Is(err, diagnostic.ErrFault) {
			t.Fatalf("malformed snapshot accepted %+v: %v", test, err)
		}
	}
	if _, err := decodeEntityRecord(map[string]json.RawMessage{"x": []byte(`{"long":9007199254740993,"string":"bad"}`)}); !errors.Is(err, diagnostic.ErrFault) {
		t.Fatalf("malformed value accepted %v", err)
	}
}

func TestEntityStoreEmptySnapshot(t *testing.T) {
	rt := &Client{}
	store, err := rt.decodeEntitySnapshot(storeOutput{
		Snapshot: []byte(`{"version":1,"entities":[]}`), Normalized: []byte(`[]`),
	})
	if err != nil || store.rt != rt {
		t.Fatalf("valid empty snapshot rejected: %+v %v", store, err)
	}
}
