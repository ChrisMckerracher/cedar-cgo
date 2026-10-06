// Command verify-native-artifact checks a native library before Go links it.
package main

import (
	"encoding/json/v2"
	"fmt"
	"os"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/artifact"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "platforms" {
		data, err := json.Marshal(artifact.Platforms)
		if err != nil {
			fail(err)
		}
		fmt.Println(string(data))
		return
	}
	if len(os.Args) >= 5 && os.Args[1] == "link-source" {
		source, err := artifact.LinkSource(os.Args[2], os.Args[4:], os.Args[3])
		if err != nil {
			fail(err)
		}
		if _, err := os.Stdout.Write(source); err != nil {
			fail(err)
		}
		return
	}
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: verify-native-artifact ARTIFACT_DIR SOURCE_COMMIT RUST_TARGET SOURCE_HEADER")
		fmt.Fprintln(os.Stderr, "       verify-native-artifact link-source PLATFORM LIBRARY_SHA256 FLAGS...")
		fmt.Fprintln(os.Stderr, "       verify-native-artifact platforms")
		os.Exit(1)
	}
	header, err := os.ReadFile(os.Args[4])
	if err == nil {
		err = artifact.Verify(os.Args[1], os.Args[2], os.Args[3], header)
	}
	if err != nil {
		fail(err)
	}
	fmt.Println("Native artifact files, source commit, target, and header match.")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
