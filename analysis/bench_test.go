package analysis_test

import (
	"context"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
)

func BenchmarkNew(b *testing.B) {
	for b.Loop() {
		a, err := analysis.New(context.Background(), solver.CVC5("cvc5"))
		if err != nil {
			b.Fatal(err)
		}
		_ = a.Close(context.Background())
	}
}
