package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectNativeIdentityMismatch(t *testing.T) {
	mutations := map[string]func(*Manifest){
		"source":           func(m *Manifest) { m.SourceCommit = strings.Repeat("a", 40) },
		"target":           func(m *Manifest) { m.Target = "aarch64-unknown-linux-gnu" },
		"platform":         func(m *Manifest) { m.Platform = "linux_arm64" },
		"ABI":              func(m *Manifest) { m.ABI++ },
		"Cedar":            func(m *Manifest) { m.Cedar = "4.12.0" },
		"SymCC":            func(m *Manifest) { m.SymCC = "0.6.0" },
		"toolchain":        func(m *Manifest) { m.Toolchain = "1.98.0" },
		"panic":            func(m *Manifest) { m.Panic = "abort" },
		"profile":          func(m *Manifest) { m.Profile = "release" },
		"files":            func(m *Manifest) { m.Files["extra"] = strings.Repeat("a", 64) },
		"linker injection": func(m *Manifest) { m.NativeStaticLibs = []string{"-L/tmp/foreign"} },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := fixture(t)
			data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			change(&m)
			data, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(dir, "manifest.json"), data)
			rewriteManifest(t, dir)
			if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
				t.Fatal("accepted changed native identity")
			}
		})
	}
}

func TestRejectHeaderAndObjectMismatch(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		dir := fixture(t)
		if err := Verify(dir, testCommit, testTarget, []byte("wrong header")); err == nil {
			t.Fatal("accepted wrong header")
		}
	})
	t.Run("object", func(t *testing.T) {
		dir := fixture(t)
		library, err := os.ReadFile(filepath.Join(dir, "libcgw_native.a"))
		if err != nil {
			t.Fatal(err)
		}
		library[8+60+18] = 183
		write(t, filepath.Join(dir, "libcgw_native.a"), library)
		data, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		updateMetadata(t, dir, m)
		if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
			t.Fatal("accepted wrong object target")
		}
	})
}

func TestRejectInjectedLinkSourceWithMatchingHashes(t *testing.T) {
	dir := fixture(t)
	data, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	link, _ := os.ReadFile(filepath.Join(dir, "link_flags.go"))
	write(t, filepath.Join(dir, "link_flags.go"), append(link, []byte("func init() {}\n")...))
	updateMetadata(t, dir, m)
	if err := Verify(dir, testCommit, testTarget, testHeader); err == nil {
		t.Fatal("accepted injected linker source")
	}
}
