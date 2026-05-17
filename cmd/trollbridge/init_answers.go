package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// answersFileV1 is the on-disk schema for `trollbridge init --answers
// <file>`. Field names are lowercase_with_underscores so the YAML
// reads idiomatically; the loader maps them onto the existing
// `initAnswers` struct.
//
// The version line at the top of the file is a structured comment:
//
//   # trollbridge-init-answers v1
//
// The loader does not require the header (YAML comments are not
// addressable), but the agentic plan emits it and the example file
// carries it so any future migration can grep for the version.
type answersFileV1 struct {
	InstallMode  string `yaml:"install_mode"`
	Topology     string `yaml:"topology"`
	Mode         string `yaml:"mode"`
	Interception bool   `yaml:"interception"`
	AuditPath    string `yaml:"audit_path,omitempty"`
	LLM          *struct {
		Enabled  bool   `yaml:"enabled"`
		Provider string `yaml:"provider,omitempty"`
		Model    string `yaml:"model,omitempty"`
		Endpoint string `yaml:"endpoint,omitempty"`
		APIKey   string `yaml:"api_key,omitempty"`
	} `yaml:"llm,omitempty"`
}

// loadAnswersFile reads an answers file from disk (or "-" for
// stdin) and returns the initAnswers struct the existing init
// rendering consumes. Strict YAML decoding rejects unknown keys
// so a typo surfaces at load time, matching the #123 convention.
func loadAnswersFile(path string, stdin io.Reader) (initAnswers, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(stdin)
		if err != nil {
			return initAnswers{}, fmt.Errorf("init: read answers from stdin: %w", err)
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return initAnswers{}, fmt.Errorf("init: read answers file %s: %w", path, err)
		}
	}

	var v answersFileV1
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown keys
	if err := dec.Decode(&v); err != nil {
		if err == io.EOF {
			return initAnswers{}, fmt.Errorf("init: answers file %s is empty", path)
		}
		return initAnswers{}, fmt.Errorf("init: invalid answers file %s: %w", path, err)
	}
	// A second document means the operator concatenated unrelated
	// YAML; matches #126 (no multi-document config).
	var trailing answersFileV1
	if err := dec.Decode(&trailing); err == nil {
		return initAnswers{}, fmt.Errorf("init: answers file %s contains more than one YAML document; combine into a single document", path)
	}

	return validateAndConvertAnswers(v, path)
}

// validateAndConvertAnswers checks required fields and the
// dependencies named in the agentic plan, then projects the
// answers-file schema onto the existing initAnswers struct.
//
// Validation errors are structured: "init: answers file <path>:
// <field>: <reason>". The agent surfaces the message verbatim; the
// reason names what to fix.
func validateAndConvertAnswers(v answersFileV1, path string) (initAnswers, error) {
	mustOneOf := func(field, got string, choices ...string) error {
		for _, c := range choices {
			if got == c {
				return nil
			}
		}
		return fmt.Errorf("init: answers file %s: %s: %q is not one of [%s]", path, field, got, strings.Join(choices, ", "))
	}

	if err := mustOneOf("install_mode", v.InstallMode, "user", "daemon"); err != nil {
		return initAnswers{}, err
	}
	if err := mustOneOf("topology", v.Topology, "local", "local-vm", "remote"); err != nil {
		return initAnswers{}, err
	}
	if err := mustOneOf("mode", v.Mode, "default-deny", "default-allow", "default-ask"); err != nil {
		return initAnswers{}, err
	}

	ans := initAnswers{
		installMode:  v.InstallMode,
		topology:     v.Topology,
		mode:         v.Mode,
		interception: v.Interception,
		auditPath:    v.AuditPath,
	}
	if v.LLM != nil && v.LLM.Enabled {
		if err := mustOneOf("llm.provider", v.LLM.Provider, "anthropic", "aoai", "other"); err != nil {
			return initAnswers{}, err
		}
		if v.LLM.Model == "" {
			return initAnswers{}, fmt.Errorf("init: answers file %s: llm.model: required when llm.enabled is true", path)
		}
		// aoai REQUIRES the endpoint URL; anthropic falls back to the
		// template default; other has no useful default so we require it.
		if v.LLM.Provider != "anthropic" && v.LLM.Endpoint == "" {
			return initAnswers{}, fmt.Errorf("init: answers file %s: llm.endpoint: required when llm.provider is %q", path, v.LLM.Provider)
		}
		ans.llmEnabled = true
		ans.llmProvider = v.LLM.Provider
		ans.llmModel = v.LLM.Model
		ans.llmEndpoint = v.LLM.Endpoint
		ans.llmKey = v.LLM.APIKey
	}
	return ans, nil
}

// sampleAnswersFile is the canonical example shown in
// config.agentic.yaml. Exported via this constant so the file and
// the loader cannot drift; the test suite asserts the constant
// loads via loadAnswersFile.
const sampleAnswersFile = `# trollbridge-init-answers v1
#
# Hand this file to: trollbridge init --answers <file>
# or pipe via stdin:  cat … | trollbridge init --answers -
#
# Required:
install_mode: user        # user | daemon  (daemon not supported on Windows)
topology: local           # local | local-vm | remote
mode: default-deny        # default-deny | default-allow | default-ask
interception: false       # true requires CA install on every consumer host

# Optional — omit to accept the install-mode defaults.
# audit_path: /var/log/trollbridge/audit.jsonl

# LLM advisor — omit the whole block to leave it off.
# llm:
#   enabled: true
#   provider: anthropic                          # anthropic | aoai | other
#   model: claude-opus-4-7
#   endpoint: https://api.anthropic.com/v1/messages
#   api_key: sk-ant-...                          # user-mode only;
#                                                # daemon-mode operators write
#                                                # the key file by hand and
#                                                # leave api_key blank here.
`
