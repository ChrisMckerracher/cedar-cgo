package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectInvalidLibraryDigest(t *testing.T) {
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("a", 64) + "\n"} {
		if _, err := LinkSource("linux_amd64", []string{"-lc"}, digest); err == nil {
			t.Fatalf("accepted invalid library digest %q", digest)
		}
	}
}

func TestRejectStaleLinkSourceAfterLibraryChange(t *testing.T) {
	dir := fixture(t)
	path := filepath.Join(dir, "libcgw_native.a")
	library, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	library[len(library)-1] ^= 1
	write(t, path, library)
	body, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	updateMetadata(t, dir, manifest)
	if err := Verify(dir, testCommit, testTarget, testHeader); err == nil || !strings.Contains(err.Error(), "generated linker source") {
		t.Fatalf("got %v, want a stale generated linker source error", err)
	}
}
