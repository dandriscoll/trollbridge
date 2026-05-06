// Package redact applies redaction modifiers to request bodies and
// header maps for the audit log. See DESIGN.md §11.4 / §15.3.
package redact

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// Config is the operator-configured set of redactors.
type Config struct {
	BodyJSONPaths []string
	BodyRegexes   []*regexp.Regexp
	QueryRegexes  []*regexp.Regexp
	HeaderModifiers []string // names from policy modifiers
}

// Compile turns string patterns into compiled regexps.
func Compile(jsonPaths, bodyPatterns, queryPatterns, headerMods []string) (*Config, error) {
	cfg := &Config{HeaderModifiers: headerMods}
	for _, p := range jsonPaths {
		cfg.BodyJSONPaths = append(cfg.BodyJSONPaths, p)
	}
	for _, p := range bodyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		cfg.BodyRegexes = append(cfg.BodyRegexes, re)
	}
	for _, p := range queryPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		cfg.QueryRegexes = append(cfg.QueryRegexes, re)
	}
	return cfg, nil
}

// Result is a redaction outcome record.
type Result struct {
	Output         []byte
	RedactedFields int
}

// Body applies redactors to a body payload. Returns a new byte
// slice and the redaction count.
func (c *Config) Body(body []byte, contentType string) Result {
	if len(body) == 0 {
		return Result{Output: body}
	}
	count := 0
	out := body

	// JSONPath redactors only fire on JSON bodies. We accept
	// `application/json` and any subtype thereof.
	if isJSON(contentType) && len(c.BodyJSONPaths) > 0 {
		var v any
		if err := json.Unmarshal(out, &v); err == nil {
			for _, p := range c.BodyJSONPaths {
				if redactJSONPath(v, p) {
					count++
				}
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err == nil {
				// Encoder appends a newline; trim it to keep the
				// body sample tight.
				out = bytes.TrimRight(buf.Bytes(), "\n")
			}
		}
	}

	// Regex redactors apply to the (already JSONPath-redacted)
	// bytes regardless of content type.
	for _, re := range c.BodyRegexes {
		if re.Match(out) {
			out = re.ReplaceAll(out, []byte("<redacted>"))
			count++
		}
	}
	return Result{Output: out, RedactedFields: count}
}

// Headers applies named modifiers to the supplied header map and
// returns a new (cloned) header map plus the count. Modifiers
// recognized: redact_authorization_header, redact_cookie. Plus a
// universal Proxy-Authorization redaction that always fires.
func (c *Config) Headers(h http.Header, ruleModifiers []string) (http.Header, int) {
	out := h.Clone()
	count := 0

	apply := func(name string) {
		if v := out.Get(name); v != "" {
			out.Set(name, "<redacted>")
			count++
		}
	}

	all := append([]string(nil), c.HeaderModifiers...)
	all = append(all, ruleModifiers...)
	for _, m := range all {
		switch m {
		case "redact_authorization_header":
			apply("Authorization")
		case "redact_cookie":
			apply("Cookie")
		}
	}
	apply("Proxy-Authorization") // always
	return out, count
}

// Query applies query-string regex redactors to a URL's raw query.
func (c *Config) Query(rawQuery string) (string, int) {
	if rawQuery == "" {
		return "", 0
	}
	count := 0
	out := rawQuery
	for _, re := range c.QueryRegexes {
		if re.MatchString(out) {
			out = re.ReplaceAllString(out, "<redacted>")
			count++
		}
	}
	return out, count
}

// SampleForAudit returns the body bytes truncated to maxBytes for
// the audit log. Sampling AFTER redaction.
func SampleForAudit(b []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 {
		return nil, false
	}
	if len(b) <= maxBytes {
		return b, false
	}
	return b[:maxBytes], true
}

func isJSON(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// redactJSONPath supports a small subset: $.field, $.a.b.c. No
// indices, no wildcards. Returns true if a value was replaced.
func redactJSONPath(v any, path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	return walkAndReplace(v, parts)
}

func walkAndReplace(v any, parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	switch m := v.(type) {
	case map[string]any:
		key := parts[0]
		if len(parts) == 1 {
			if _, ok := m[key]; ok {
				m[key] = "<redacted>"
				return true
			}
			return false
		}
		if next, ok := m[key]; ok {
			return walkAndReplace(next, parts[1:])
		}
	}
	return false
}

// nonEmptyBuf is just a sentinel to avoid importing bytes only for
// the empty check.
var nonEmptyBuf = bytes.NewBufferString("")
