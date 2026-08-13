package secsuite

import "testing"

// Table-driven tests are the Go convention and the style the rest of the port
// should follow: one slice of cases, one loop, t.Run so each case gets its own
// name in the failure output.
func TestSeverityRank(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     int
	}{
		{"critical is most severe", SeverityCritical, 0},
		{"high outranks medium", SeverityHigh, 1},
		{"info is least severe of the known values", SeverityInfo, 4},
		// The reason Rank exists in this shape: an unrecognized severity must
		// sort last. indexOf's -1 in the TypeScript version would have made it
		// beat "critical" in dedupe's severity comparison.
		{"unknown sorts after info", Severity("banana"), 5},
		{"empty sorts after info", Severity(""), 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.Rank(); got != tt.want {
				t.Errorf("Severity(%q).Rank() = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}
