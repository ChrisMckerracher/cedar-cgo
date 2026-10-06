package performance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ChrisMckerracher/cedar-cgo/cedar"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/batched"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
	"github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
)

type checkpoint struct {
	Completed int
	RSSBytes  int64
	GoHeap    uint64
}

func memoryCheckpoint(t testing.TB, completed int) checkpoint {
	t.Helper()
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	var resident int64
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/statm")
		if err != nil {
			t.Fatal(err)
		}
		pages, err := strconv.ParseInt(strings.Fields(string(data))[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		resident = pages * int64(os.Getpagesize())
	} else {
		data, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
		if err != nil {
			t.Fatal(err)
		}
		kilobytes, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		resident = kilobytes * 1024
	}
	return checkpoint{completed, resident, memory.HeapAlloc}
}

func authorizationCycle(t testing.TB, calls *atomic.Uint64) (uint64, uint64) {
	t.Helper()
	runtime, err := cedar.NewRuntime(context.Background(), cedar.WithMaxConcurrentCalls(2))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())
	authorizer, err := runtime.NewAuthorizer(context.Background(), callbackConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Close()
	loader := batched.EntityLoaderFunc(func(context.Context, []uid.EntityUID) (batched.EntityLoadResult, error) {
		calls.Add(1)
		return batched.EntityLoadResult{Entities: json.RawMessage(callbackEntities)}, nil
	})
	decision, err := authorizer.Batched().AuthorizeBatched(context.Background(), callbackRequest(), loader, batched.BatchedOptions{MaxIterations: 4})
	if err != nil || decision != request.Allow {
		t.Fatal(decision, err)
	}
	stats := authorizer.Stats()
	return stats.Created, stats.Discarded
}

func compiledCycle(t testing.TB) *solverCounts {
	t.Helper()
	analyzer, counts := measuredAnalyzer(t)
	defer analyzer.Close(context.Background())
	source, first, second := analysisInputs()
	session, err := analyzer.OpenCompiled(context.Background(), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	handleA, err := session.Compile(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	handleB, err := session.Compile(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	report, err := session.Equivalent(context.Background(), handleA, handleB)
	if err != nil || !report.Holds() {
		t.Fatal(report, err)
	}
	for _, handle := range []struct{ release func() error }{
		{func() error { return session.Release(context.Background(), handleA) }},
		{func() error { return session.Release(context.Background(), handleB) }},
	} {
		if err := handle.release(); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func TestNativeResourceTrend(t *testing.T) {
	if os.Getenv("CVC5") == "" {
		t.Skip("CVC5 is required for resource measurements")
	}
	var result struct {
		Cycles, CompiledReleases                                  int
		AuthorizationCreated, AuthorizationDiscarded, LoaderCalls uint64
		SolverStarts, SolverCloses, SolverReads, SolverWrites     uint64
		Checkpoints                                               []checkpoint
	}
	var calls atomic.Uint64
	result.Checkpoints = append(result.Checkpoints, memoryCheckpoint(t, 0))
	for result.Cycles < 100 {
		created, discarded := authorizationCycle(t, &calls)
		counts := compiledCycle(t)
		result.AuthorizationCreated += created
		result.AuthorizationDiscarded += discarded
		result.SolverStarts += counts.started.Load()
		result.SolverCloses += counts.closed.Load()
		result.SolverReads += counts.reads.Load()
		result.SolverWrites += counts.writes.Load()
		result.CompiledReleases += 2
		result.Cycles++
		if result.Cycles%20 == 0 {
			result.Checkpoints = append(result.Checkpoints, memoryCheckpoint(t, result.Cycles))
		}
	}
	result.LoaderCalls = calls.Load()
	if result.AuthorizationCreated != 100 || result.AuthorizationDiscarded != 0 || result.LoaderCalls < 100 || result.SolverStarts != 100 || result.SolverCloses != 100 {
		t.Fatalf("resource ownership counts differ: %+v", result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}
