package artifact

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"
const testTarget = "x86_64-unknown-linux-gnu"

var testHeader = []byte("native ABI 2 header\n")

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	object := make([]byte, 64)
	copy(object, "\x7fELF")
	object[4], object[5] = 2, 1
	binary.LittleEndian.PutUint16(object[18:20], 62)
	library := append([]byte("!<arch>\n"), []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", "test.o/", 0, 0, 0, 0644, len(object)))...)
	library = append(library, object...)
	write(t, filepath.Join(dir, "libcgw_native.a"), library)
	write(t, filepath.Join(dir, "cedar.h"), testHeader)
	link, _ := LinkSource("linux_amd64", []string{"-lc"}, fmt.Sprintf("%x", sha256.Sum256(library)))
	write(t, filepath.Join(dir, "link_flags.go"), link)
	write(t, filepath.Join(dir, "SOURCE_COMMIT"), []byte(testCommit+"\n"))
	m := Manifest{ABI: 2, SourceCommit: testCommit, Target: testTarget, Platform: "linux_amd64", Cedar: "4.13.0", SymCC: "0.7.0", Toolchain: "1.99.0", Profile: "native", Panic: "unwind", NativeStaticLibs: []string{"-lc"}}
	updateMetadata(t, dir, m)
	return dir
}

func updateMetadata(t *testing.T, dir string, m Manifest) {
	t.Helper()
	m.Files = make(map[string]string)
	for _, name := range []string{"libcgw_native.a", "cedar.h", "link_flags.go"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		m.Files[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "manifest.json"), body)
	rewriteManifest(t, dir)
}

func rewriteManifest(t *testing.T, dir string) {
	t.Helper()
	var manifest string
	for _, name := range paths {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		manifest += fmt.Sprintf("%x  %s\n", sha256.Sum256(data), name)
	}
	write(t, filepath.Join(dir, "SHA256SUMS"), []byte(manifest))
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
