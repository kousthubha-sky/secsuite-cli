package secsuite

import (
	"slices"
	"strconv"
)

// dedupeKey is file + line + category. Category (the normalized classification)
// stands in for "mapped rule/CWE" here - ruleId vocabularies never overlap
// between tools, so keying on raw ruleId would never catch the most common real
// duplicate (e.g. trivy's secret scanner and gitleaks both flagging the same
// hardcoded key on the same line).
// ponytail: no CWE extraction, category is the simple stand-in. Upgrade to
// real CWE matching if false-merges show up in practice.
func dedupeKey(f Finding) string {
	line := ""
	if f.Location.StartLine != 0 {
		line = strconv.Itoa(f.Location.StartLine)
	}
	return f.Location.File + ":" + line + ":" + string(f.Category)
}

// DedupeFindings merges genuine cross-tool duplicates and preserves input order.
//
// The order slice is not decoration. A JavaScript Map iterates in insertion
// order, so the TypeScript version got ordering for free; ranging a Go map
// yields keys in a randomized sequence, so without this the report would list
// findings differently on every single run.
func DedupeFindings(findings []Finding) []Finding {
	byKey := make(map[string]*Finding, len(findings))
	order := make([]string, 0, len(findings))

	for _, f := range findings {
		key := dedupeKey(f)
		existing, seen := byKey[key]

		if !seen {
			byKey[key] = copyFinding(f)
			order = append(order, key)
			continue
		}

		// Merge only when a DIFFERENT tool reports the same location+category -
		// that is a genuine cross-tool duplicate (e.g. trivy and gitleaks both
		// flagging one hardcoded key). Two findings from the SAME tool at one
		// location are distinct issues - several CVEs on one dependency line, or
		// several ZAP alerts on one URL - so they must be kept separate.
		if !slices.Contains(existing.Sources, string(f.Tool)) {
			for _, source := range f.Sources {
				if !slices.Contains(existing.Sources, source) {
					existing.Sources = append(existing.Sources, source)
				}
			}
			if f.Severity.Rank() < existing.Severity.Rank() {
				existing.Severity = f.Severity
			}
			continue
		}

		// Same tool, same location+category: re-key with ruleId so the distinct
		// finding survives instead of being collapsed. An identical
		// tool+rule+location finding (a true duplicate) still folds into one.
		// ponytail: a same-tool finding won't also cross-tool-merge here; add that
		// if a tool ever re-reports another tool's exact location+category+rule.
		ruleKey := key + ":" + f.RuleID
		if _, seen := byKey[ruleKey]; !seen {
			order = append(order, ruleKey)
		}
		byKey[ruleKey] = copyFinding(f)
	}

	merged := make([]Finding, 0, len(order))
	for _, key := range order {
		merged = append(merged, *byKey[key])
	}
	return merged
}

// copyFinding returns a pointer to a copy of f whose Sources slice is its own.
//
// Assigning a struct in Go copies it, so `merged := f` is already a copy - but
// a slice field still points at the same backing array, and appending to the
// merged finding's Sources could overwrite the caller's data.
func copyFinding(f Finding) *Finding {
	merged := f
	merged.Sources = slices.Clone(f.Sources)
	return &merged
}
