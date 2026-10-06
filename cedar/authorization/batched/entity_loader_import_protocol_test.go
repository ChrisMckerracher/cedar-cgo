package batched

import (
	diagnostic "github.com/ChrisMckerracher/cedar-cgo/cedar/diagnostic"

	"context"
	"encoding/json"
	"errors"

	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
	"testing"
)

func TestEntityLoaderImportProtocol(t *testing.T) {
	for _, mode := range []string{"absent_state", "out_of_range", "invalid_json", "over_limit", "read_without_load", "wrong_read_length", "bad_read_pointer", "repeat_load", "exhausted_calls", "round_trip"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := &EntityLoaderState{maxBatch: 256, remaining: 512, maxCalls: 1, loader: EntityLoaderFunc(func(_ context.Context, ids []uid.EntityUID) (EntityLoadResult, error) {
				calls++
				if len(ids) != 1 || ids[0] != (uid.EntityUID{Type: "User", ID: "a"}) {
					t.Fatalf("wrong ids %v", ids)
				}
				return EntityLoadResult{Missing: ids}, nil
			})}
			request := []byte(`[{"type":"User","id":"a"}]`)
			ctx := context.Background()
			switch mode {
			case "absent_state":
				if LoadEntityBatch(ctx, nil, request) != -1 {
					t.Fatal("absent state accepted")
				}
				return
			case "out_of_range":
				request = nil
			case "invalid_json":
				request[0] = '!'
			case "over_limit":
				request = make([]byte, 257)
			case "read_without_load":
				if n, e := s.Call(ctx, 2, make([]byte, 10)); n != -1 || e == nil {
					t.Fatal("read accepted without result")
				}
				return
			case "exhausted_calls":
				s.calls = 1
			}
			size, err := s.Call(ctx, 1, request)
			switch mode {
			case "round_trip", "wrong_read_length", "bad_read_pointer", "repeat_load":
				if size <= 0 || calls != 1 || err != nil {
					t.Fatalf("load failed: %d %d %v", size, calls, err)
				}
				if mode == "repeat_load" {
					if n, e := s.Call(ctx, 1, request); n != -1 || calls != 1 || e == nil {
						t.Fatal("repeated load accepted")
					}
					return
				}
				if mode == "wrong_read_length" {
					size++
				}
				buffer := make([]byte, size)
				if mode == "bad_read_pointer" {
					buffer = nil
				}
				status, e := s.Call(ctx, 2, buffer)
				if mode != "round_trip" {
					if status != -1 || e == nil {
						t.Fatal("invalid read accepted")
					}
					return
				}
				if status != 0 || e != nil || s.pending != nil {
					t.Fatal("result not consumed")
				}
				var body struct{ Missing []struct{ Type, ID string } }
				if e := json.Unmarshal(buffer, &body); e != nil || len(body.Missing) != 1 || body.Missing[0].ID != "a" {
					t.Fatalf("copied result %v %v", body, e)
				}
				if n, e := s.Call(ctx, 2, buffer); n != -1 || e == nil {
					t.Fatal("repeated read accepted")
				}
			default:
				if size != -1 || calls != 0 || err == nil {
					t.Fatalf("invalid request accepted: %d calls=%d error=%v", size, calls, err)
				}
			}
		})
	}
}
func TestEncodeEntityLoadResultExactBudget(t *testing.T) {
	data := EntityLoadResult{Entities: json.RawMessage(`[]`)}
	for i := 0; i < 40; i++ {
		data.Missing = append(data.Missing, uid.EntityUID{Type: "U", ID: ""})
	}
	body, e := EncodeEntityLoadResult(data, 4096)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := EncodeEntityLoadResult(data, len(body)); e != nil {
		t.Fatal(e)
	}
	_, e = EncodeEntityLoadResult(data, len(body)-1)
	var ce *diagnostic.Error
	if !errors.As(e, &ce) || ce.Kind != diagnostic.KindLimit {
		t.Fatal(e)
	}
}
