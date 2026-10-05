package batched

import (
	json "encoding/json"
	errors "errors"
	diagnostic "github.com/ChrisMckerracher/cedar-go-wasm/cedar/diagnostic"
	entityuid "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"

	testing "testing"
)

func TestEntityLoaderRejectsInvalidUTF8(t *testing.T) {
	bad := string([]byte{0xff})
	for _, result := range []EntityLoadResult{
		{Entities: json.RawMessage(`[{"uid":{"type":"User","id":"` + bad + `"}}]`)},
		{Missing: []entityuid.EntityUID{{Type: "User", ID: bad}}},
		{Missing: []entityuid.EntityUID{{Type: bad, ID: "a"}}},
	} {
		body, err := EncodeEntityLoadResult(result, 4096)
		var e *diagnostic.Error
		if body != nil || !errors.As(err, &e) || e.Kind != diagnostic.KindInput {
			t.Fatalf("malformed loader result: %s %v; want KindInput", body, err)
		}
	}
}
