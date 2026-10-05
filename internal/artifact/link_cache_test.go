package artifact

import "testing"

func TestLibraryDigestInvalidatesCgoBuildCache(t *testing.T) {
	f := newCgoCacheFixture(t)
	first := f.archive(17)
	f.linkerSource(first)
	if value := f.binaryValue(); value != "17" {
		t.Fatalf("first archive: got %s, want 17", value)
	}
	second := f.archive(43)
	if first == second {
		t.Fatal("changed native code retained the same library digest")
	}
	// The unchanged Go source demonstrates the external-library cache failure.
	if value := f.binaryValue(); value != "17" {
		t.Fatalf("cache control: got %s, want the unchanged cached value 17", value)
	}
	f.linkerSource(second)
	if value := f.binaryValue(); value != "43" {
		t.Fatalf("regenerated linker source: got %s, want 43", value)
	}
}
