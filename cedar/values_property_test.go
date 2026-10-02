package cedar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cedar "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"pgregory.net/rapid"
)

// remarshal preserves exact integer tokens through json.Number.
func propRemarshal(t *rapid.T, data []byte) []byte {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Cedar value JSON reaches a fixpoint after one parse→marshal round trip.
func TestPropertyValueJSONFixpoint(t *testing.T) {
	rapid.Check(t, func(pt *rapid.T) {
		value := propGenValue(2).Draw(pt, "value")
		first, err := json.Marshal(value)
		if err != nil {
			pt.Fatalf("marshal: %v", err)
		}
		second := propRemarshal(pt, first)
		third := propRemarshal(pt, second)
		if !bytes.Equal(second, third) {
			pt.Fatalf("value JSON is not a fixpoint: %s vs %s", second, third)
		}
	})
}

// Entity snapshots pass their raw JSON through unchanged on marshal.
func TestPropertyEntitiesJSONPassthrough(t *testing.T) {
	joyJSON := readFile(t, "../testdata/joy/entities.json")
	rapid.Check(t, func(pt *rapid.T) {
		first, err := json.Marshal(propGenEntityStore(joyJSON).Draw(pt, "store").entities)
		if err != nil {
			pt.Fatalf("marshal: %v", err)
		}
		again, err := json.Marshal(cedar.EntitiesFromJSON(first))
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
	d := loadJoy(t)
	rt := testRuntime(t)
	joyJSON := readFile(t, "../testdata/joy/entities.json")
	ctx := context.Background()
	start := time.Now()
	rapid.Check(t, func(pt *rapid.T) {
		if !propWithinBudget(start, 5*time.Second) {
			return
		}
		var raw []byte
		switch rapid.IntRange(0, 2).Draw(pt, "kind") {
		case 0:
			raw = rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(pt, "bytes")
		case 1:
			valid := propGenEntityStore(joyJSON).Draw(pt, "store").raw(pt)
			raw = valid[:rapid.IntRange(0, len(valid)).Draw(pt, "cut")]
		default:
			// Mutating an alphanumeric byte keeps the JSON valid but changes IDs,
			// exercising both the accepted and rejected fail-closed paths.
			valid := propGenEntityStore(joyJSON).Draw(pt, "store").raw(pt)
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
		if nesting(string(raw)) > maxFuzzNesting {
			return
		}
		for _, schema := range []*cedar.Schema{&d.schema, nil} {
			a, err := rt.NewAuthorizer(ctx, cedar.Config{
				Policies: permitAll, Entities: cedar.EntitiesFromJSON(raw), Schema: schema, Limits: fuzzLimits,
			})
			propCheckNoFault(pt, err)
			if err != nil {
				continue
			}
			resp, err := a.Authorize(ctx, joyRequest())
			a.Close()
			propCheckNoFault(pt, err)
			if err != nil && resp.Decision != cedar.Deny {
				pt.Fatalf("error %v came with %v", err, resp.Decision)
			}
		}
	})
}

func propCheckNoFault(t *rapid.T, err error) {
	t.Helper()
	if errors.Is(err, cedar.ErrFault) {
		t.Fatalf("module fault: %v", err)
	}
}
