// Package configwrite mutates `lists.allow` and `lists.deny` inside a
// trollbridge.yaml file in place, preserving comments and structure
// outside the touched subtree.
//
// Comments outside the lists subtree (head comments on top-level
// keys, comments around the ports block, etc.) survive. Comments
// attached to individual list entries are best-effort: a re-emit
// preserves them, but the relative ordering of a comment vs. a
// sorted-resorted entry may shift.
package configwrite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/hostlist"
	"gopkg.in/yaml.v3"
)

// AddAllow inserts pattern into the file's `lists.allow` sequence,
// re-sorts ascending, and writes the file atomically. It is
// idempotent: returns (false, nil) when pattern already present.
func AddAllow(path, pattern string) (bool, error) {
	return mutate(path, "allow", func(entries []string) []string {
		return insertSorted(entries, pattern)
	})
}

// AddDeny inserts pattern into `lists.deny`. Same semantics as
// AddAllow.
func AddDeny(path, pattern string) (bool, error) {
	return mutate(path, "deny", func(entries []string) []string {
		return insertSorted(entries, pattern)
	})
}

// Generalize applies an accepted generalization to `list` ("allow" or
// "deny") in one atomic write: it removes each entry in removeSources
// (the more-specific patterns the generalization replaces — #173) and
// inserts the generalized pattern. A source not present is skipped.
// Returns (changed, err); changed is true when the resulting list
// differs from the original (normally true, since the pattern is
// added).
func Generalize(path, list, pattern string, removeSources []string) (bool, error) {
	if list != "allow" && list != "deny" {
		return false, fmt.Errorf("generalize: unknown list %q", list)
	}
	srcSet := map[string]struct{}{}
	for _, s := range removeSources {
		srcSet[strings.TrimSpace(s)] = struct{}{}
	}
	return mutate(path, list, func(entries []string) []string {
		var kept []string
		for _, e := range entries {
			// Drop an entry if it was an explicit source OR if the
			// generalized pattern already covers it (#177): a wider
			// method, dropped port, wildcarded path, or wildcarded host
			// all make the specific entry redundant. The new pattern is
			// re-added below, so an entry equal to it round-trips.
			if _, isSrc := srcSet[strings.TrimSpace(e)]; isSrc || hostlist.Subsumes(pattern, e) {
				continue
			}
			kept = append(kept, e)
		}
		return insertSorted(kept, pattern)
	})
}

// RemoveAllow removes every occurrence of pattern from
// `lists.allow`. Returns (false, nil) when no occurrence exists.
func RemoveAllow(path, pattern string) (bool, error) {
	return mutate(path, "allow", func(entries []string) []string {
		return remove(entries, pattern)
	})
}

// RemoveDeny removes every occurrence of pattern from `lists.deny`.
func RemoveDeny(path, pattern string) (bool, error) {
	return mutate(path, "deny", func(entries []string) []string {
		return remove(entries, pattern)
	})
}

// OperatorApprove records the operator's "allow this pattern"
// decision in trollbridge.yaml. It is the consolidate-then-add
// primitive every operator-action persistence path MUST use to
// avoid leaving the pattern on both lists (closes #194, prior
// recurrence #179).
//
// Implementation: removes the pattern from `lists.deny` (best-
// effort — a missing entry is not an error) then adds it to
// `lists.allow`. Returns:
//
//   - removed: true when an entry on deny was removed (the
//     consolidation step did something).
//   - changed: true when the allow list was actually mutated
//     (AddAllow is idempotent; existing pattern → changed=false).
//   - removeErr / addErr: errors from each step. removeErr is
//     non-fatal in production callers (they log and continue);
//     addErr is fatal (the add is the operator's intent).
//
// Used by:
//   - cmd/trollbridge/run.go SetDecisionPersist callback (every
//     in-process operator approve via the TUI hold queue).
//   - internal/console/console.go addPattern (every `allow X` /
//     console-issued list edit, including the TUI's retroactive
//     approve / +add / edit / undo paths).
//
// Adding a NEW operator-action persist path? Route it through
// here. Calling AddAllow directly from a NEW path will
// re-introduce the #194 recurrence shape; the structural test
// at internal/server/persist_consolidation_test.go enumerates
// known callers explicitly.
func OperatorApprove(path, pattern string) (removed, changed bool, removeErr, addErr error) {
	removed, removeErr = RemoveDeny(path, pattern)
	changed, addErr = AddAllow(path, pattern)
	return
}

// OperatorDeny is the symmetric counterpart to OperatorApprove
// (closes #194): removes the pattern from allow, adds it to deny.
// Same caller discipline applies — operator-action persist paths
// MUST use this, not AddDeny directly.
func OperatorDeny(path, pattern string) (removed, changed bool, removeErr, addErr error) {
	removed, removeErr = RemoveAllow(path, pattern)
	changed, addErr = AddDeny(path, pattern)
	return
}

// DeclinedSuggestion is the on-disk shape recorded by
// AddDeclinedSuggestion. Mirrors config.DeclinedSuggestion (kept
// local to avoid an import cycle between configwrite and config).
type DeclinedSuggestion struct {
	SourceEntries []string
	AxesDeclined  []string
	DeclinedAt    string // RFC3339
}

// AddDeclinedSuggestion appends one row to `lists.declined_suggestions`,
// or no-ops if a row with the same canonical source-entry set already
// exists. The auto-managed marker comment is attached to the section
// the first time it is created. Returns (changed, err).
func AddDeclinedSuggestion(path string, set DeclinedSuggestion) (bool, error) {
	if len(set.SourceEntries) == 0 {
		return false, errors.New("declined suggestion has no source entries")
	}
	canonical := append([]string(nil), set.SourceEntries...)
	sort.Strings(canonical)
	set.SourceEntries = canonical

	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("%s: top-level is not a mapping", path)
	}
	doc := root.Content[0]

	listsNode := findOrCreateMappingChild(doc, "lists")
	// Locate the existing declined_suggestions sequence, or create
	// it. New section gets the auto-managed marker comment so a
	// human opening the YAML knows not to hand-edit.
	seqNode, created := findOrCreateSeqChildWithComment(
		listsNode,
		"declined_suggestions",
		"Automatically managed — do not edit by hand.\n"+
			"trollbridge appends one row per declined generalization\n"+
			"suggestion so the same source-entry set is never re-offered.",
	)

	if !created {
		for _, existing := range seqNode.Content {
			if existing.Kind != yaml.MappingNode {
				continue
			}
			if sameCanonicalSourceEntries(existing, canonical) {
				return false, nil
			}
		}
	}

	rowNode := buildDeclinedRow(set)
	seqNode.Content = append(seqNode.Content, rowNode)

	blanks := captureBlankLines(data)

	out, err := encodeNode(&root)
	if err != nil {
		return false, fmt.Errorf("encode: %w", err)
	}
	out = reinsertBlankLines(out, blanks)
	return true, atomicWrite(path, out, 0o600)
}

func findOrCreateSeqChildWithComment(parent *yaml.Node, key, comment string) (*yaml.Node, bool) {
	for i := 0; i < len(parent.Content)-1; i += 2 {
		if parent.Content[i].Value == key {
			child := parent.Content[i+1]
			if child.Kind != yaml.SequenceNode {
				child.Kind = yaml.SequenceNode
				child.Tag = "!!seq"
				child.Value = ""
				child.Content = nil
			}
			return child, false
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key, HeadComment: comment}
	valNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode, true
}

func sameCanonicalSourceEntries(row *yaml.Node, canonical []string) bool {
	for i := 0; i < len(row.Content)-1; i += 2 {
		if row.Content[i].Value != "source_entries" {
			continue
		}
		seq := row.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			return false
		}
		existing := stringsFromSeq(seq)
		sorted := append([]string(nil), existing...)
		sort.Strings(sorted)
		if len(sorted) != len(canonical) {
			return false
		}
		for j := range sorted {
			if sorted[j] != canonical[j] {
				return false
			}
		}
		return true
	}
	return false
}

func buildDeclinedRow(set DeclinedSuggestion) *yaml.Node {
	row := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	addPair := func(k string, v *yaml.Node) {
		row.Content = append(row.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			v,
		)
	}
	seSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, e := range set.SourceEntries {
		seSeq.Content = append(seSeq.Content, &yaml.Node{
			Kind: yaml.ScalarNode, Tag: "!!str", Value: e,
		})
	}
	addPair("source_entries", seSeq)
	if len(set.AxesDeclined) > 0 {
		axSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, a := range set.AxesDeclined {
			axSeq.Content = append(axSeq.Content, &yaml.Node{
				Kind: yaml.ScalarNode, Tag: "!!str", Value: a,
			})
		}
		addPair("axes_declined", axSeq)
	}
	if set.DeclinedAt != "" {
		addPair("declined_at", &yaml.Node{
			Kind: yaml.ScalarNode, Tag: "!!str", Value: set.DeclinedAt,
		})
	}
	return row
}

// mutate is the common path: parse the file as a Node, find or
// create lists.<which>, apply transform, encode, and atomically
// rewrite. Returns (changed, err).
func mutate(path, which string, transform func([]string) []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("%s: top-level is not a mapping", path)
	}
	doc := root.Content[0]

	listsNode := findOrCreateMappingChild(doc, "lists")
	seqNode := findOrCreateSeqChild(listsNode, which)

	current := stringsFromSeq(seqNode)
	updated := transform(current)
	if equalSlices(current, updated) {
		return false, nil
	}
	replaceSeqContent(seqNode, updated)

	blanks := captureBlankLines(data)

	out, err := encodeNode(&root)
	if err != nil {
		return false, fmt.Errorf("encode: %w", err)
	}
	out = reinsertBlankLines(out, blanks)
	return true, atomicWrite(path, out, 0o600)
}

// blankAnchor records that `blankBefore` empty lines preceded the
// line `line` in the original source. Used to re-insert blank lines
// after yaml.v3 round-trips them out.
type blankAnchor struct {
	line        string
	blankBefore int
}

// captureBlankLines scans src and records the run of blank lines
// preceding each non-blank line, in document order. Trailing blank
// lines (after the last non-blank line) are dropped — yaml.v3
// already emits a single trailing newline.
func captureBlankLines(src []byte) []blankAnchor {
	lines := strings.Split(string(src), "\n")
	var anchors []blankAnchor
	blankRun := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blankRun++
			continue
		}
		if blankRun > 0 {
			anchors = append(anchors, blankAnchor{
				line:        strings.TrimRight(line, " \t"),
				blankBefore: blankRun,
			})
		}
		blankRun = 0
	}
	return anchors
}

// reinsertBlankLines walks encoded line-by-line and, when a line
// matches the next anchor in order, emits that anchor's blank-line
// run first. Anchors that never match (encoder reformatted the line)
// are skipped — degrades to "no blank inserted there," matching
// previous behavior.
func reinsertBlankLines(encoded []byte, anchors []blankAnchor) []byte {
	if len(anchors) == 0 {
		return encoded
	}
	lines := strings.Split(string(encoded), "\n")
	out := make([]string, 0, len(lines)+len(anchors))
	ai := 0
	for _, line := range lines {
		if ai < len(anchors) && strings.TrimRight(line, " \t") == anchors[ai].line {
			for n := 0; n < anchors[ai].blankBefore; n++ {
				out = append(out, "")
			}
			ai++
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

// findOrCreateMappingChild looks up `key` under a mapping node,
// returning its value node. Creates an empty mapping value if not
// present (appends to the parent's Content).
func findOrCreateMappingChild(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(parent.Content)-1; i += 2 {
		if parent.Content[i].Value == key {
			child := parent.Content[i+1]
			if child.Kind != yaml.MappingNode {
				child.Kind = yaml.MappingNode
				child.Tag = "!!map"
				child.Value = ""
				child.Content = nil
			}
			return child
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}

// findOrCreateSeqChild looks up `key` under a mapping node,
// returning its sequence value. Creates an empty sequence if not
// present.
func findOrCreateSeqChild(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(parent.Content)-1; i += 2 {
		if parent.Content[i].Value == key {
			child := parent.Content[i+1]
			if child.Kind != yaml.SequenceNode {
				child.Kind = yaml.SequenceNode
				child.Tag = "!!seq"
				child.Value = ""
				child.Content = nil
			}
			return child
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}

func stringsFromSeq(seq *yaml.Node) []string {
	out := make([]string, 0, len(seq.Content))
	for _, n := range seq.Content {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
	}
	return out
}

func replaceSeqContent(seq *yaml.Node, entries []string) {
	seq.Content = nil
	seq.Style = 0 // block style — nicer diffs
	for _, e := range entries {
		seq.Content = append(seq.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: e,
		})
	}
}

func insertSorted(entries []string, pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return entries
	}
	for _, e := range entries {
		if e == pattern {
			return entries
		}
	}
	out := append([]string(nil), entries...)
	out = append(out, pattern)
	sort.Strings(out)
	return out
}

func remove(entries []string, pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	out := entries[:0:0]
	for _, e := range entries {
		if e == pattern {
			continue
		}
		out = append(out, e)
	}
	return out
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func encodeNode(n *yaml.Node) ([]byte, error) {
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// atomicWrite writes data to a sibling tempfile and renames it over
// path. Preserves the operator's mode if the file exists.
func atomicWrite(path string, data []byte, fallbackMode os.FileMode) error {
	mode := fallbackMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".trollbridge-yaml-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	// fsync the file before close so the new bytes survive a crash
	// between rename and the next checkpoint. Cheap; matches the
	// "flushed right away" wording in #49. Errors here are not fatal —
	// some filesystems / mounts (e.g. tmpfs in some configurations)
	// return ENOSYS or EINVAL; treat as best-effort.
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return errors.Join(err, fmt.Errorf("rename %s -> %s", tmpPath, path))
	}
	// fsync the parent directory so the rename itself is durable.
	// Best-effort; same caveat as the file fsync above.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
