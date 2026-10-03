package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestActionQueryResultJSONRoundTrip(t *testing.T) {
	for _, result := range []ActionQueryResult{
		{},
		{Allowed: []EntityUID{}, Undecided: []EntityUID{}},
		{Allowed: []EntityUID{NewEntityUID("App::Action", "view/雪\n")}, Undecided: []EntityUID{NewEntityUID("App::Action", "")}},
	} {
		data, err := json.Marshal(result)
		if err != nil || strings.Contains(string(data), "__entity") {
			t.Fatalf("query result did not preserve flat UIDs: %s %v", data, err)
		}
		var reparsed ActionQueryResult
		if err := json.Unmarshal(data, &reparsed); err != nil || !reflect.DeepEqual(result, reparsed) {
			t.Fatalf("query result JSON changed data: %+v %v", reparsed, err)
		}
	}
	for _, result := range []ActionQueryResult{
		{Allowed: []EntityUID{NewEntityUID(string([]byte{255}), "view")}},
		{Allowed: []EntityUID{NewEntityUID("Action", string([]byte{255}))}},
		{Undecided: []EntityUID{NewEntityUID(string([]byte{255}), "edit")}},
		{Undecided: []EntityUID{NewEntityUID("Action", string([]byte{255}))}},
	} {
		if _, err := json.Marshal(result); err == nil {
			t.Fatal("query result accepted invalid UTF-8")
		}
	}
}

func TestPermissionQueryProtocol(t *testing.T) {
	for _, raw := range []string{`{}`, `{"allowed":null}`, `{"allowed":[{}]}`, `{"allowed":[{"type":"User","id":null}]}`, `{"allowed":[{"type":"User","id":"x"},{"type":"User","id":"x"}]}`, `{"allowed":[],"undecided":null}`, `{"allowed":[{"type":"Action","id":"x"}],"undecided":[{"type":"Action","id":"x"}]}`} {
		if _, err := decodeQuery([]byte(raw), true); err == nil {
			t.Errorf("accepted malformed query %s", raw)
		}
	}
	got, err := decodeQuery([]byte(`{"allowed":[],"undecided":[{"type":"Action","id":""}]}`), true)
	if err != nil || len(got.Undecided) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestPermissionQueryLimitsBeforeGuest(t *testing.T) {
	a := &Authorizer{limits: Limits{MaxRequestBytes: 1}}
	ctx := context.Background()
	_, err := a.QueryResources(ctx, ResourceQueryRequest{})
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatal(err)
	}
	_, err = a.QueryPrincipals(ctx, PrincipalQueryRequest{})
	if !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatal(err)
	}
	_, err = a.QueryActions(ctx, ActionQueryRequest{})
	if !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatal(err)
	}
	_, err = a.QueryResources(ctx, ResourceQueryRequest{ResourceType: string([]byte{0xff})})
	if !errors.As(err, &ce) || ce.Kind != KindInput {
		t.Fatal(err)
	}
	_, err = a.QueryPrincipals(ctx, PrincipalQueryRequest{PrincipalType: string([]byte{0xff})})
	if !errors.As(err, &ce) || ce.Kind != KindInput {
		t.Fatal(err)
	}
}
