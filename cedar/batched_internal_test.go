package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tetratelabs/wazero/api"
)

type batchMemory struct {
	api.Memory
	bytes []byte
}

func (m batchMemory) Read(ptr, n uint32) ([]byte, bool) {
	if uint64(ptr)+uint64(n) > uint64(len(m.bytes)) {
		return nil, false
	}
	return m.bytes[ptr : ptr+n], true
}
func (m batchMemory) Write(ptr uint32, b []byte) bool {
	if uint64(ptr)+uint64(len(b)) > uint64(len(m.bytes)) {
		return false
	}
	copy(m.bytes[ptr:], b)
	return true
}

type batchModule struct {
	api.Module
	mem    batchMemory
	closed bool
}

func (m *batchModule) Memory() api.Memory                              { return m.mem }
func (m *batchModule) CloseWithExitCode(context.Context, uint32) error { m.closed = true; return nil }

func TestEntityLoaderImportProtocol(t *testing.T) {
	for _, mode := range []string{"absent_state", "out_of_range", "invalid_json", "over_limit", "read_without_load", "wrong_read_length", "bad_read_pointer", "repeat_load", "exhausted_calls", "round_trip"} {
		t.Run(mode, func(t *testing.T) {
			m := &batchModule{mem: batchMemory{bytes: make([]byte, 4096)}}
			request := []byte(`[{"type":"User","id":"a"}]`)
			m.mem.Write(0, request)
			calls := 0
			state := &entityLoaderState{maxBatch: 256, remaining: 512, maxCalls: 1, loader: EntityLoaderFunc(func(_ context.Context, ids []EntityUID) (EntityLoadResult, error) {
				calls++
				if len(ids) != 1 || ids[0] != (EntityUID{Type: "User", ID: "a"}) {
					t.Fatalf("wrong ids %v", ids)
				}
				return EntityLoadResult{Missing: ids}, nil
			})}
			ctx := context.WithValue(context.Background(), entityLoaderKey{}, state)
			ptr, n := uint32(0), uint32(len(request))
			switch mode {
			case "absent_state":
				ctx = context.Background()
			case "out_of_range":
				ptr = ^uint32(0)
			case "invalid_json":
				m.mem.bytes[0] = '!'
			case "over_limit":
				n = 257
			case "read_without_load":
				if readEntityBatch(ctx, m, 0, 10) != -1 || !m.closed {
					t.Fatal("read accepted without result")
				}
				return
			case "exhausted_calls":
				state.calls = 1
			}
			size := loadEntityBatch(ctx, m, ptr, n)
			switch mode {
			case "round_trip", "wrong_read_length", "bad_read_pointer", "repeat_load":
				if size <= 0 || calls != 1 || m.closed {
					t.Fatalf("load failed: %d %d %v", size, calls, state.err)
				}
				switch mode {
				case "repeat_load":
					if loadEntityBatch(ctx, m, 0, uint32(len(request))) != -1 || calls != 1 || !m.closed {
						t.Fatal("repeated load accepted")
					}
					return
				case "wrong_read_length":
					size++
				case "bad_read_pointer":
					ptr = ^uint32(0)
				}
				status := readEntityBatch(ctx, m, ptr, uint32(size))
				if mode != "round_trip" {
					if status != -1 || !m.closed {
						t.Fatal("invalid read accepted")
					}
					return
				}
				if status != 0 || state.pending != nil {
					t.Fatal("result not consumed")
				}
				var body struct{ Missing []struct{ Type, ID string } }
				if err := json.Unmarshal(m.mem.bytes[:size], &body); err != nil || len(body.Missing) != 1 || body.Missing[0].ID != "a" {
					t.Fatalf("copied result %v %v", body, err)
				}
				if readEntityBatch(ctx, m, 0, uint32(size)) != -1 || !m.closed {
					t.Fatal("repeated read accepted")
				}
			default:
				if size != -1 || calls != 0 || (mode != "absent_state" && !m.closed) {
					t.Fatalf("invalid request accepted: %d calls=%d closed=%t", size, calls, m.closed)
				}
			}
		})
	}
}

func TestEncodeEntityLoadResultExactBudget(t *testing.T) {
	data := EntityLoadResult{Entities: json.RawMessage(`[]`)}
	for i := 0; i < 40; i++ {
		data.Missing = append(data.Missing, EntityUID{Type: "U", ID: ""})
	}
	body, err := encodeEntityLoadResult(data, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encodeEntityLoadResult(data, len(body)); err != nil {
		t.Fatalf("exact budget rejected: %v", err)
	}
	_, err = encodeEntityLoadResult(data, len(body)-1)
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindLimit {
		t.Fatalf("limit not enforced: %v", err)
	}
}
