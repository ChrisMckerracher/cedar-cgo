package analysis_test

import (
	"context"
	"testing"

	schemas "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
)

func BenchmarkRepeatedEquivalent(b *testing.B) {
	ctx := context.Background()
	schema := schemas.SchemaFromCedar(querySchema)
	firstPolicies := queryPolicy("permit", "context.n < 0")
	secondPolicies := queryPolicy("permit", "context.n <= -1")
	b.Run("stateless", func(b *testing.B) {
		a, _ := compiledAnalyzer(b)
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			report, err := a.Equivalent(ctx, schema, firstPolicies, secondPolicies)
			if err != nil || !report.Holds() {
				b.Fatalf("equivalence %+v %v", report, err)
			}
		}
	})
	b.Run("compiled", func(b *testing.B) {
		a, _ := compiledAnalyzer(b)
		s, err := a.OpenCompiled(ctx, schema, nil)
		if err != nil {
			b.Fatal(err)
		}
		first, err := s.Compile(ctx, firstPolicies)
		if err != nil {
			b.Fatal(err)
		}
		second, err := s.Compile(ctx, secondPolicies)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.Equivalent(ctx, first, second); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			report, err := s.Equivalent(ctx, first, second)
			if err != nil || !report.Holds() {
				b.Fatalf("equivalence %+v %v", report, err)
			}
		}
	})
}
