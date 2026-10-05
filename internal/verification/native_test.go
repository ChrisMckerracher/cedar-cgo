package verification

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Source checks bind the arithmetic proof to the reviewed native response and handle guards.
func TestNativeABIProofSource(t *testing.T) {
	checks := map[string][]string{
		"../native/bridge.go": {
			"if result.status > 1 {",
			"result.data == nil || result.len == 0 || uint64(result.len) > uint64(maxResponse)",
			"unsafe.Slice((*byte)(unsafe.Pointer(result.data)), int(result.len))",
			"defer C.cgw_native_free(result)",
		},
		"../native/callback_export.go": {
			"uint64(size) > uint64(^uint(0)>>1)",
		},
		"../../rust/crates/native/src/entries.rs": {
			"checked_add(1)",
		},
		"../../rust/crates/analysis/src/sessions/compile.rs": {
			"checked_add(1)",
		},
	}
	for path, expressions := range checks {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, expression := range expressions {
			if !strings.Contains(string(data), expression) {
				t.Errorf("%s: %s changed; review native.smt2", path, expression)
			}
		}
	}
}

func TestNativeABIProof(t *testing.T) {
	solver := os.Getenv("CVC5")
	if solver == "" {
		t.Skip("CVC5 is not set; see docs/verification.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, solver, "--lang=smt2", "native.smt2").CombinedOutput()
	if err != nil {
		t.Fatalf("cvc5: %v\n%s", err, output)
	}
	if strings.Join(strings.Fields(string(output)), " ") != "unsat unsat unsat" {
		t.Fatalf("expected three proved properties, got:\n%s", output)
	}
	t.Log("proved: accepted response lengths fit signed 64-bit int and uint32 limit; checked handle increment is monotonic")
}
