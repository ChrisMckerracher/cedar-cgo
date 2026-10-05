// Command verify-native-artifact checks a native library before Go links it.
package main

import (
	"fmt"
	"os"

	"github.com/ChrisMckerracher/cedar-go-wasm/internal/artifact"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: verify-native-artifact ARTIFACT_DIR SOURCE_COMMIT RUST_TARGET SOURCE_HEADER")
		os.Exit(1)
	}
	header, err := os.ReadFile(os.Args[4])
	if err == nil {
		err = artifact.Verify(os.Args[1], os.Args[2], os.Args[3], header)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Native artifact files, source commit, target, and header match.")
}
