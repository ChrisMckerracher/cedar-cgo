package cedar

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/wasmhost"
)

// BenchmarkInstanceMemory reports the Go heap and the linear memory that
// one loaded instance of the joy authorizer holds.
func BenchmarkInstanceMemory(b *testing.B) {
	read := func(name string) string {
		data, err := os.ReadFile("testdata/joy/" + name)
		if err != nil {
			b.Fatal(err)
		}
		return string(data)
	}
	schema := SchemaFromCedar(read("joy.cedarschema"))
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close(ctx)
	a, err := rt.NewAuthorizer(ctx, Config{
		Schema:   &schema,
		Policies: PoliciesFromCedar(read("old.cedar")),
		Entities: EntitiesFromJSON([]byte(read("entities.json"))),
	})
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	const n = 20
	for b.Loop() {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		insts := make([]*wasmhost.Instance, n)
		for i := range insts {
			if insts[i], err = a.newInstance(ctx); err != nil {
				b.Fatal(err)
			}
		}
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/n, "heap-bytes/instance")
		b.ReportMetric(float64(insts[0].MemoryBytes()), "linear-bytes/instance")
		for _, inst := range insts {
			_ = inst.Close(ctx)
		}
	}
}
