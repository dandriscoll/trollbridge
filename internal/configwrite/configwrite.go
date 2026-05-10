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

	out, err := encodeNode(&root)
	if err != nil {
		return false, fmt.Errorf("encode: %w", err)
	}
	return true, atomicWrite(path, out, 0o600)
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
	return nil
}
