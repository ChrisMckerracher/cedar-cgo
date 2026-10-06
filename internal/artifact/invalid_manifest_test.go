package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectInvalidNativeManifest(t *testing.T) {
	for _, data := range [][]byte{[]byte("{"), []byte(`{"unexpected":true}`)} {
		dir := fixture(t)
		write(t, filepath.Join(dir, "manifest.json"), data)
		if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
			t.Fatal("accepted invalid manifest")
		}
	}
	dir := fixture(t)
	if err := Verify(dir, testCommit, "x86_64-pc-windows-gnu", testHeader); err == nil {
		t.Fatal("accepted unsupported target")
	}
	if err := Verify(filepath.Join(dir, "missing"), testCommit, testTarget, testHeader); err == nil {
		t.Fatal("accepted missing directory")
	}
}

func TestRejectDuplicateManifestMembers(t *testing.T) {
	for _, nested := range []bool{false, true} {
		dir := fixture(t)
		path := filepath.Join(dir, "manifest.json")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if nested {
			text = strings.Replace(text, `"files":{`, `"files":{"cedar.h":"duplicate",`, 1)
		} else {
			text = `{"abi":2,` + text[1:]
		}
		write(t, path, []byte(text))
		rewriteManifest(t, dir)
		if err := Verify(dir, testCommit, testTarget, testHeader); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("got %v, want duplicate member rejection", err)
		}
	}
}

func TestRejectInvalidManifestUTF8(t *testing.T) {
	dir := fixture(t)
	path := filepath.Join(dir, "manifest.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), testCommit, "\xff"+testCommit[1:], 1))
	write(t, path, body)
	rewriteManifest(t, dir)
	if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
		t.Fatal("accepted invalid manifest UTF-8")
	}
}

func TestRejectTrailingNativeManifest(t *testing.T) {
	for _, suffix := range []string{"{}", "garbage"} {
		dir := fixture(t)
		path := filepath.Join(dir, "manifest.json")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		write(t, path, append(body, suffix...))
		rewriteManifest(t, dir)
		if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
			t.Fatal("accepted trailing manifest data")
		}
	}
}

func TestRejectMissingAndCorruptedNativeFiles(t *testing.T) {
	for _, name := range paths {
		t.Run(name, func(t *testing.T) {
			dir := fixture(t)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
				t.Fatal("accepted missing file")
			}
		})
	}
	for _, name := range []string{"cedar.h", "libcgw_native.a", "link_flags.go"} {
		t.Run("corrupt "+name, func(t *testing.T) {
			dir := fixture(t)
			write(t, filepath.Join(dir, name), []byte("corrupt"))
			rewriteManifest(t, dir)
			if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
				t.Fatal("accepted corrupted file")
			}
		})
	}
	dir := fixture(t)
	body, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m.NativeStaticLibs = nil
	updateMetadata(t, dir, m)
	if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
		t.Fatal("accepted missing linker requirements")
	}
	if _, err := LinkSource("bad", []string{"-lc"}, ""); err == nil {
		t.Fatal("accepted invalid platform")
	}
}
