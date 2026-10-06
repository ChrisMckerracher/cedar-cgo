package authorization

import (
	"context"

	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/execution"
	"github.com/ChrisMckerracher/cedar-go-wasm/internal/native"
)

// Process RSS includes Rust allocations that Go heap measurements exclude.
func processResidentBytes() (int64, error) {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			return 0, err
		}
		pages, err := strconv.ParseInt(strings.Fields(string(data))[1], 10, 64)
		return pages * int64(os.Getpagesize()), err
	}
	data, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0, err
	}
	kilobytes, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return kilobytes * 1024, err
}

func BenchmarkInstanceMemory(b *testing.B) {
	read := func(name string) string {
		data, err := os.ReadFile("../../testdata/joy/" + name)
		if err != nil {
			b.Fatal(err)
		}
		return string(data)
	}
	source := schema.SchemaFromCedar(read("joy.cedarschema"))
	ctx := context.Background()
	rt, err := execution.New(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close(ctx)
	a, err := NewAuthorizer(ctx, rt, Config{
		Schema: &source, Policies: policy.PoliciesFromCedar(read("old.cedar")),
		Entities: entity.EntitiesFromJSON([]byte(read("entities.json"))),
	})
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	const count = 20
	for b.Loop() {
		runtime.GC()
		beforeRSS, err := processResidentBytes()
		if err != nil {
			b.Fatal(err)
		}
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		instances := make([]*native.Instance, count)
		for i := range instances {
			if instances[i], err = a.session.NewInstance(ctx); err != nil {
				b.Fatal(err)
			}
		}
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		afterRSS, err := processResidentBytes()
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/count, "heap-bytes/instance")
		b.ReportMetric(float64(afterRSS-beforeRSS)/count, "rss-delta-bytes/instance")
		b.ReportMetric(float64(afterRSS), "rss-bytes/process")
		for _, instance := range instances {
			if err := instance.Close(ctx); err != nil {
				b.Fatal(err)
			}
		}
	}
}
