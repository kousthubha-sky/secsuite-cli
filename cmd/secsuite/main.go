// Command secsuite is a stack-aware security scanning CLI: it detects a
// repository's tech stack, runs the appropriate open-source scanners, and
// merges their results into a single report.
package main

import (
	"fmt"
	"os"
)

// version is overwritten at release time with -ldflags="-X main.version=...".
var version = "dev"

func main() {
	// Everything except report output goes to stderr, so `secsuite scan --json -`
	// stays pipeable. Worth establishing on line one rather than retrofitting.
	fmt.Fprintf(os.Stderr, "secsuite %s\n", version)
}
