package integration_test

import (
	corpus "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/corpus"
	testruntime "github.com/ChrisMckerracher/cedar-cgo/internal/testsupport/runtime"

	os "os"
	filepath "path/filepath"
	runtime "runtime"
	slices "slices"
	strings "strings"
	sync "sync"
	testing "testing"
)

// CEDAR_CORPUS_DIR must contain corpus-tests/ from the pinned upstream archive.
func TestCorpus(t *testing.T) {
	dir := os.Getenv("CEDAR_CORPUS_DIR")
	if dir == "" {
		t.Skip("CEDAR_CORPUS_DIR is not set; see CONTRIBUTING.md")
	}
	files, err := filepath.Glob(filepath.Join(dir, "corpus-tests", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	files = slices.DeleteFunc(files, func(f string) bool { return strings.HasSuffix(f, ".entities.json") })
	if len(files) != 7523 {
		t.Fatalf("corpus has %d test files; want 7523 from the pinned archive", len(files))
	}
	rt := testruntime.New(t)
	var tally corpus.CorpusTally
	work := make(chan string)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for f := range work {
				corpus.RunCorpusTest(rt, dir, f, &tally)
			}
		})
	}
	for _, f := range files {
		work <- f
	}
	close(work)
	wg.Wait()

	t.Logf("tests=%d requests=%d decisionMismatch=%d reasonMismatch=%d errorMismatch=%d validationMismatch=%d setupFailure=%d requestFailure=%d",
		tally.Tests, tally.Requests, tally.DecisionMismatch, tally.ReasonMismatch, tally.ErrorMismatch,
		tally.ValidationMismatch, tally.SetupFailure, tally.RequestFailure)
	for _, e := range tally.Examples {
		t.Log(e)
	}
	if tally.DecisionMismatch+tally.ReasonMismatch+tally.ErrorMismatch+tally.ValidationMismatch+tally.SetupFailure+tally.RequestFailure != 0 {
		t.Fatal("the corpus disagrees with this package")
	}
	if tally.Tests != 7523 || tally.Requests != 60184 {
		t.Fatalf("incomplete corpus: tests=%d requests=%d; want 7523 tests and 60184 requests", tally.Tests, tally.Requests)
	}
}
