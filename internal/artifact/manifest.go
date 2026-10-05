package artifact

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

var Platforms = map[string]string{
	"x86_64-unknown-linux-gnu":  "linux_amd64",
	"aarch64-unknown-linux-gnu": "linux_arm64",
	"aarch64-apple-darwin":      "darwin_arm64",
}

type Manifest struct {
	ABI              uint32            `json:"abi"`
	SourceCommit     string            `json:"source_commit"`
	Target           string            `json:"target"`
	Platform         string            `json:"platform"`
	Cedar            string            `json:"cedar"`
	SymCC            string            `json:"symcc"`
	Toolchain        string            `json:"toolchain"`
	Profile          string            `json:"profile"`
	Panic            string            `json:"panic"`
	NativeStaticLibs []string          `json:"native_static_libs"`
	Files            map[string]string `json:"files"`
}

func (m Manifest) verify(commit, target string, files map[string][]byte) error {
	if m.SourceCommit != commit {
		return fmt.Errorf("manifest source commit does not match")
	}
	if m.Target != target || m.Platform != Platforms[target] {
		return fmt.Errorf("manifest target does not match")
	}
	if m.ABI != 2 {
		return fmt.Errorf("manifest ABI does not match")
	}
	if m.Cedar != "4.13.0" || m.SymCC != "0.7.0" || m.Toolchain != "1.99.0" || m.Profile != "native" || m.Panic != "unwind" {
		return fmt.Errorf("manifest build inputs do not match")
	}
	if len(m.Files) != 3 {
		return fmt.Errorf("manifest file set does not match")
	}
	for _, name := range []string{"cedar.h", "libcgw_native.a", "link_flags.go"} {
		if m.Files[name] != fmt.Sprintf("%x", sha256.Sum256(files[name])) {
			return fmt.Errorf("manifest %s hash does not match", name)
		}
	}
	expected, err := LinkSource(m.Platform, m.NativeStaticLibs, m.Files["libcgw_native.a"])
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, files["link_flags.go"]) {
		return fmt.Errorf("generated linker source does not match native requirements")
	}
	return nil
}
