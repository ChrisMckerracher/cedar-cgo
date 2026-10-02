package analysis_test

import (
	"context"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
)

// BenchmarkNew measures compiling the analysis module with no cache.
func BenchmarkNew(b *testing.B) {
	for b.Loop() {
		a, err := analysis.New(context.Background(), analysis.CVC5("cvc5"))
		if err != nil {
			b.Fatal(err)
		}
		_ = a.Close(context.Background())
	}
}
