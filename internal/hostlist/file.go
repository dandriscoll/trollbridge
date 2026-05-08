package hostlist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadLines reads `path` and returns its lines (newline-stripped).
// A missing file is treated as an empty list. Errors other than
// "not exist" are returned.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// WriteLines writes `lines` to `path` atomically (write to tmp +
// rename). Mode 0644.
func WriteLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".trollbridge-list-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	body := strings.Join(lines, "\n")
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpName, path, err)
	}
	return nil
}

// ValidatePattern checks the pattern parses as a Pattern; returns
// an error suitable for the operator to read.
func ValidatePattern(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return fmt.Errorf("empty pattern")
	}
	if _, err := parsePattern(pattern); err != nil {
		return err
	}
	return nil
}
