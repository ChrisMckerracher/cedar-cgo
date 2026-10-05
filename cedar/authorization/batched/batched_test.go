package batched_test

import (
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"

	context "context"
	json "encoding/json"
	errors "errors"

	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	batched "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/batched"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
	testsupport "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport"

	reflect "reflect"
	testing "testing"
)

func TestBatchedNativeParity(t *testing.T) {
	data, err := fixture.ReadFile("../testdata/parity/batched/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Name, Decision string
		Error          *string
		Calls          [][]testsupport.BatchUID
	}
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	fixtures := testsupport.BatchedFixtures(t)
	if len(fixtures) != len(expected) {
		t.Fatal("native fixture count differs")
	}
	for i, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			want := expected[i]
			if want.Name != f.Name {
				t.Fatal("native fixture order differs")
			}
			a := testsupport.BatchAuthorizer(t, f, authorization.Limits{})
			calls := make([][]testsupport.BatchUID, 0)
			loader := batched.EntityLoaderFunc(func(_ context.Context, uids []entityuid.EntityUID) (batched.EntityLoadResult, error) {
				call := make([]testsupport.BatchUID, len(uids))
				for i, u := range uids {
					call[i] = testsupport.BatchUID{Type: u.Type, ID: u.ID}
				}
				result := testsupport.FixtureBatch(f, len(calls))
				calls = append(calls, call)
				return result, nil
			})
			decision, err := a.Batched().AuthorizeBatched(context.Background(), testsupport.BatchRequest(f), loader, batched.BatchedOptions{MaxIterations: f.MaxIterations})
			if decision.String() != want.Decision {
				t.Fatalf("decision %s, native %s", decision, want.Decision)
			}
			if want.Error == nil {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var ce *diagnostic.Error
				if !errors.As(err, &ce) || ce.Kind != diagnostic.KindBatched || ce.Message != *want.Error {
					t.Fatalf("error %v, native %s", err, *want.Error)
				}
			}
			if !reflect.DeepEqual(calls, want.Calls) {
				t.Fatalf("callback trace %v, native %v", calls, want.Calls)
			}
		})
	}
}

func TestBatchedCallbackFailures(t *testing.T) {
	f := testsupport.BatchedFixtures(t)[0]
	sentinel := errors.New("database unavailable")
	for _, tt := range []struct {
		name   string
		loader batched.EntityLoaderFunc
		kind   diagnostic.ErrorKind
		cause  error
	}{
		{"error", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{}, sentinel
		}, diagnostic.KindLoader, sentinel},
		{"panic", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			panic("callback panic")
		}, diagnostic.KindLoader, nil},
		{"malformed", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Entities: json.RawMessage("[")}, nil
		}, diagnostic.KindLoader, nil},
		{"wrong_shape", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Entities: json.RawMessage(`null`)}, nil
		}, diagnostic.KindEntities, nil},
		{"wrong_type", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Entities: json.RawMessage(`[{"uid":{"type":"User","id":"alice"},"attrs":{"enabled":"yes"},"parents":[]}]`)}, nil
		}, diagnostic.KindEntities, nil},
		{"duplicate", func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
			return batched.EntityLoadResult{Missing: []entityuid.EntityUID{{Type: "User", ID: "alice"}, {Type: "User", ID: "alice"}}}, nil
		}, diagnostic.KindEntities, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := testsupport.BatchAuthorizer(t, f, authorization.Limits{MaxInstances: 1})
			d, err := a.Batched().AuthorizeBatched(context.Background(), testsupport.BatchRequest(f), tt.loader, batched.BatchedOptions{MaxIterations: 4})
			var ce *diagnostic.Error
			if d != cedarrequest.Deny || !errors.As(err, &ce) || ce.Kind != tt.kind {
				t.Fatalf("got %s %v", d, err)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Fatalf("lost callback cause: %v", err)
			}
			n := 0
			d, err = a.Batched().AuthorizeBatched(context.Background(), testsupport.BatchRequest(f), batched.EntityLoaderFunc(func(context.Context, []entityuid.EntityUID) (batched.EntityLoadResult, error) {
				out := testsupport.FixtureBatch(f, n)
				n++
				return out, nil
			}), batched.BatchedOptions{MaxIterations: 2})
			if d != cedarrequest.Allow || err != nil {
				t.Fatalf("recovery got %s %v", d, err)
			}
		})
	}
}
