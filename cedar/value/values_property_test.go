package value_test

import (
	fault "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fault"
	fixture "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fixture"
	fuzz "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/fuzz"
	generator "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/generator"
	joy "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/joy"
	testruntime "github.com/ChrisMckerracher/cedar-go-wasm/internal/testsupport/runtime"

	bytes "bytes"
	context "context"
	json "encoding/json"
	authorization "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
	cedarrequest "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
	cedarentity "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	cedarschema "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"

	rapid "pgregory.net/rapid"
	testing "testing"
)

// Cedar value JSON reaches a fixpoint after one parse→marshal round trip.
func TestPropertyValueJSONFixpoint(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		value := generator.PropGenValue(2).Draw(pt, "value")
		first, err := json.Marshal(value)
		if err != nil {
			pt.Fatalf("marshal: %v", err)
		}
		second := generator.PropRemarshal(pt, first)
		third := generator.PropRemarshal(pt, second)
		if !bytes.Equal(second, third) {
			pt.Fatalf("value JSON is not a fixpoint: %s vs %s", second, third)
		}
	})
}

// Entity snapshots pass their raw JSON through unchanged on marshal.
func TestPropertyEntitiesJSONPassthrough(t *testing.T) {
	joyJSON := fixture.MustReadFile(t, "../testdata/joy/entities.json")
	rapid.Check(t, func(pt *rapid.T) {
		first, err := json.Marshal(generator.PropGenEntityStore(joyJSON).Draw(pt, "store").Entities)
		if err != nil {
			pt.Fatalf("marshal: %v", err)
		}
		again, err := json.Marshal(cedarentity.EntitiesFromJSON(first))
		if err != nil {
			pt.Fatalf("remarshal: %v", err)
		}
		if !bytes.Equal(first, again) {
			pt.Fatalf("entity JSON is not a fixpoint: %s vs %s", first, again)
		}
	})
}

// Malformed entity input fails closed: no module fault, and any error denies.
func TestPropertyMalformedEntitiesFailClosed(t *testing.T) {
	d := joy.LoadJoy(t)
	rt := testruntime.New(t)
	joyJSON := fixture.MustReadFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	rapid.Check(t, func(pt *rapid.T) {
		var raw []byte
		switch rapid.IntRange(0, 2).Draw(pt, "kind") {
		case 0:
			raw = rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(pt, "bytes")
		case 1:
			valid := generator.PropGenEntityStore(joyJSON).Draw(pt, "store").Raw(pt)
			raw = valid[:rapid.IntRange(0, len(valid)).Draw(pt, "cut")]
		default:
			// Mutating an alphanumeric byte keeps the JSON valid but changes IDs,
			// exercising both the accepted and rejected fail-closed paths.
			valid := generator.PropGenEntityStore(joyJSON).Draw(pt, "store").Raw(pt)
			var positions []int
			for i, b := range valid {
				if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
					positions = append(positions, i)
				}
			}
			pos := rapid.SampledFrom(positions).Draw(pt, "pos")
			valid[pos] = byte('a' + rapid.IntRange(0, 25).Draw(pt, "letter"))
			raw = valid
		}
		if fuzz.Nesting(string(raw)) > fuzz.MaxFuzzNesting {
			pt.Skip("entity input exceeds the nesting limit")
		}
		for _, schema := range []*cedarschema.Schema{&d.Schema, nil} {
			a, err := rt.NewAuthorizer(ctx, authorization.Config{
				Policies: fault.PermitAll, Entities: cedarentity.EntitiesFromJSON(raw), Schema: schema, Limits: fuzz.FuzzLimits,
			})
			generator.PropCheckNoFault(pt, err)
			if err != nil {
				continue
			}
			resp, err := a.Authorize(ctx, joy.JoyRequest())
			a.Close()
			generator.PropCheckNoFault(pt, err)
			if err != nil && resp.Decision != cedarrequest.Deny {
				pt.Fatalf("error %v came with %v", err, resp.Decision)
			}
		}
	})
}
