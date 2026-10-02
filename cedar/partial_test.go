package cedar_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
)

type partialFixtureRequest struct {
	Principal cedar.PartialEntityUID
	Action    cedar.EntityUID
	Resource  cedar.PartialEntityUID
	Context   json.RawMessage
	Entities  json.RawMessage
}

func (r partialFixtureRequest) partial() cedar.PartialRequest {
	var ctx *cedar.Context
	if string(r.Context) != "null" {
		c := cedar.ContextFromJSON(r.Context)
		ctx = &c
	}
	return cedar.PartialRequest{
		Principal: r.Principal, Action: r.Action, Resource: r.Resource, Context: ctx,
		Entities: cedar.PartialEntitiesFromJSON(r.Entities),
	}
}

func (r partialFixtureRequest) concrete() cedar.Request {
	return cedar.Request{
		Principal: cedar.NewEntityUID(r.Principal.Type, *r.Principal.ID), Action: r.Action,
		Resource: cedar.NewEntityUID(r.Resource.Type, *r.Resource.ID),
		Context:  cedar.ContextFromJSON(r.Context), Entities: cedar.EntitiesFromJSON(r.Entities),
	}
}

type partialFixtureResult struct {
	ErrorStage    string `json:"error_stage"`
	Decision      string
	Reasons       []string
	Residuals     []cedar.ResidualPolicy
	ErrorPolicies []string `json:"error_policies"`
	Completions   []partialFixtureResult
}

func TestPartialNativeFixtures(t *testing.T) {
	var input struct {
		Schema string
		Cases  []struct {
			Name, Policies string
			PoliciesJSON   json.RawMessage `json:"policies_json"`
			Loaded         json.RawMessage
			Partial        partialFixtureRequest
			Completions    []partialFixtureRequest
		}
	}
	var expected []struct {
		Name   string
		Result partialFixtureResult
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/partial/input.json"), &input); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, "../testdata/parity/partial/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(input.Cases) {
		t.Fatal("fixture count mismatch")
	}
	ctx := context.Background()
	schema := cedar.SchemaFromCedar(input.Schema)
	for i, tc := range input.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := expected[i]
			if want.Name != tc.Name {
				t.Fatal("fixture order mismatch")
			}
			policies := cedar.PoliciesFromCedar(tc.Policies)
			if tc.PoliciesJSON != nil {
				policies = cedar.PoliciesFromJSON(tc.PoliciesJSON)
			}
			a, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{
				Schema: &schema, Policies: policies, Entities: cedar.EntitiesFromJSON(tc.Loaded),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			got, err := a.PartialAuthorize(ctx, tc.Partial.partial())
			if want.Result.ErrorStage != "" {
				requirePartialError(t, got, err, cedar.ErrorKind(want.Result.ErrorStage))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision.String() != want.Result.Decision || !reflect.DeepEqual(got.Reasons, want.Result.Reasons) || !reflect.DeepEqual(got.Residuals, want.Result.Residuals) {
				t.Fatalf("native/Wasm disagreement:\n got %+v\nwant %+v", got, want.Result)
			}
			if len(tc.Completions) != len(want.Result.Completions) {
				t.Fatal("completion count mismatch")
			}
			for j, c := range tc.Completions {
				r, err := got.Reauthorize(ctx, c.concrete())
				w := want.Result.Completions[j]
				if w.ErrorStage != "" {
					var ce *cedar.Error
					if r.Decision != cedar.Deny || !errors.As(err, &ce) || string(ce.Kind) != w.ErrorStage {
						t.Fatalf("completion %d: %+v %v, want %s", j, r, err, w.ErrorStage)
					}
					continue
				}
				ids := make([]string, 0, len(r.Errors))
				for _, e := range r.Errors {
					ids = append(ids, e.PolicyID)
				}
				if err != nil || r.Decision.String() != w.Decision || !reflect.DeepEqual(r.Reasons, w.Reasons) || !reflect.DeepEqual(ids, w.ErrorPolicies) {
					t.Fatalf("completion %d: %+v %v, want %+v", j, r, err, w)
				}
			}
		})
	}
}

func requirePartialError(t testing.TB, response cedar.PartialResponse, err error, kind cedar.ErrorKind) {
	t.Helper()
	var ce *cedar.Error
	if response.Decision != cedar.Undecided || !errors.As(err, &ce) || ce.Kind != kind {
		t.Fatalf("got %+v, %v; want undecided and %s", response, err, kind)
	}
}

const partialSchema = `entity User; entity Photo; action view appliesTo { principal: User, resource: Photo, context: {mfa: Bool} };`

func partialRequest() cedar.PartialRequest {
	return cedar.PartialRequest{
		Principal: cedar.UnknownEntityUID("User"), Action: cedar.NewEntityUID("Action", "view"), Resource: cedar.UnknownEntityUID("Photo"),
	}
}

func partialAuthorizer(t testing.TB, limits cedar.Limits) *cedar.Authorizer {
	t.Helper()
	schema := cedar.SchemaFromCedar(partialSchema)
	a, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{
		Schema: &schema, Policies: cedar.PoliciesFromCedar("permit(principal, action, resource) when { context.mfa };"), Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestPartialTypedEntitiesAndSnapshot(t *testing.T) {
	ctx := context.Background()
	schema := cedar.SchemaFromCedar("entity User; entity Photo {private: Bool}; action view appliesTo {principal: User, resource: Photo, context: {}};")
	a, err := testRuntime(t).NewAuthorizer(ctx, cedar.Config{
		Schema: &schema, Policies: cedar.PoliciesFromCedar("permit(principal, action, resource) when { resource.private };"),
		Limits: cedar.Limits{MaxInstances: 2, RecycleMemoryBytes: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	uid := cedar.NewEntityUID("Photo", "one")
	empty := cedar.Record{}
	req := partialRequest()
	req.Resource = cedar.KnownEntityUID(uid)
	req.Context = &cedar.Context{}
	req.Entities = cedar.NewPartialEntities(cedar.PartialEntity{UID: uid, Parents: []cedar.EntityUID{}, Tags: &empty})
	res, err := a.PartialAuthorize(ctx, req)
	if err != nil || res.Decision != cedar.Undecided {
		t.Fatalf("partial: %+v %v", res, err)
	}
	*req.Resource.ID = "mutated"
	res.Decision = cedar.PartialAllow
	res.Residuals[0].Cedar = "permit(principal, action, resource);"
	concrete := cedar.Request{Principal: cedar.NewEntityUID("User", "alice"), Action: req.Action, Resource: uid,
		Entities: cedar.NewEntities(cedar.Entity{UID: uid, Attrs: cedar.Record{"private": cedar.Bool(false)}})}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			r, err := res.Reauthorize(ctx, concrete)
			if err != nil || r.Decision != cedar.Deny {
				t.Errorf("snapshot reauthorize: %+v %v", r, err)
			}
		})
	}
	wg.Wait()
	if a.Stats().Created < 2 {
		t.Fatal("continuation did not survive instance replacement")
	}
}

func TestPartialInputErrors(t *testing.T) {
	a := partialAuthorizer(t, cedar.Limits{MaxRequestBytes: 1024})
	for name, data := range map[string]string{"malformed": "[", "wrong_shape": "{}", "wrong_type": `[{"uid":{"type":"Photo","id":"one"},"parents":false}]`} {
		t.Run(name, func(t *testing.T) {
			req := partialRequest()
			req.Entities = cedar.PartialEntitiesFromJSON([]byte(data))
			r, err := a.PartialAuthorize(context.Background(), req)
			if err == nil || r.Decision != cedar.Undecided {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	req := partialRequest()
	req.Principal.Type = strings.Repeat("x", 2048)
	r, err := a.PartialAuthorize(context.Background(), req)
	requirePartialError(t, r, err, cedar.KindLimit)
	r, err = a.PartialAuthorize(context.Background(), partialRequest())
	if err != nil {
		t.Fatal(err)
	}
	c := simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(true), "big": cedar.String(strings.Repeat("x", 2048))}))
	resp, err := r.Reauthorize(context.Background(), c)
	var ce *cedar.Error
	if resp.Decision != cedar.Deny || !errors.As(err, &ce) || ce.Kind != cedar.KindLimit {
		t.Fatalf("%+v %v", resp, err)
	}
	resp, err = (cedar.PartialResponse{}).Reauthorize(context.Background(), c)
	if resp.Decision != cedar.Deny || err == nil {
		t.Fatalf("zero continuation: %+v %v", resp, err)
	}
	without, err := testRuntime(t).NewAuthorizer(context.Background(), cedar.Config{Policies: permitAll})
	if err != nil {
		t.Fatal(err)
	}
	defer without.Close()
	r, err = without.PartialAuthorize(context.Background(), partialRequest())
	requirePartialError(t, r, err, cedar.KindSchema)
}

func TestPartialCancellationAndClose(t *testing.T) {
	a := partialAuthorizer(t, cedar.Limits{MaxInstances: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := a.PartialAuthorize(ctx, partialRequest())
	if r.Decision != cedar.Undecided || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = a.PartialAuthorize(context.Background(), partialRequest())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Reauthorize(ctx, simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(true)})))
	if resp.Decision != cedar.Deny || !errors.Is(err, context.Canceled) {
		t.Fatalf("%+v %v", resp, err)
	}
	a.Close()
	resp, err = r.Reauthorize(context.Background(), simpleRequest(cedar.Context{}))
	if resp.Decision != cedar.Deny || err == nil {
		t.Fatalf("closed: %+v %v", resp, err)
	}
}

func TestPartialExecutionTimeout(t *testing.T) {
	a := partialAuthorizer(t, cedar.Limits{MaxInstances: 1, CallTimeout: 20 * time.Millisecond, MaxRequestBytes: 8 << 20})
	req := partialRequest()
	var data strings.Builder
	data.WriteByte('[')
	for i := range 10000 {
		if i > 0 {
			data.WriteByte(',')
		}
		fmt.Fprintf(&data, `{"uid":{"type":"User","id":"%d"},"attrs":{},"parents":[],"tags":{}}`, i)
	}
	data.WriteByte(']')
	req.Entities = cedar.PartialEntitiesFromJSON([]byte(data.String()))
	start := time.Now()
	r, err := a.PartialAuthorize(context.Background(), req)
	if r.Decision != cedar.Undecided || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cedar.ErrFault) {
		t.Fatalf("%+v %v", r, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation failed to bound execution")
	}
	if a.Stats().Discarded != 1 {
		t.Fatalf("faulted instance retained: %+v", a.Stats())
	}
	r, err = a.PartialAuthorize(context.Background(), partialRequest())
	if err != nil || r.Decision != cedar.Undecided {
		t.Fatalf("recovery: %+v %v", r, err)
	}
	concrete := simpleRequest(cedar.NewContext(cedar.Record{"mfa": cedar.Bool(true)}))
	concrete.Entities = cedar.EntitiesFromJSON([]byte(data.String()))
	resp, err := r.Reauthorize(context.Background(), concrete)
	if resp.Decision != cedar.Deny || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reauthorize timeout: %+v %v", resp, err)
	}
	if a.Stats().Discarded != 2 {
		t.Fatalf("reauthorize retained fault: %+v", a.Stats())
	}
	concrete.Entities = cedar.Entities{}
	resp, err = r.Reauthorize(context.Background(), concrete)
	if err != nil || resp.Decision != cedar.Allow {
		t.Fatalf("reauthorize recovery: %+v %v", resp, err)
	}
}
