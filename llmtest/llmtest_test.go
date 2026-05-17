//go:build llmtest

// Live-LLM regression suite for trollbridge (closes #133).
//
// Run with:
//
//   export TROLLBRIDGE_LLM_TEST_CONFIG=/path/to/trollbridge.yaml
//   make llm-test
//
// Each bundle under llmtest/bundles/*.yaml becomes a t.Run subtest;
// each case in a bundle dispatches one live LLM call and asserts
// on the returned verdict + confidence. Without the
// TROLLBRIDGE_LLM_TEST_CONFIG env var the suite t.Skip()s with a
// pointer to this file.
//
// The suite is gated behind the `llmtest` build tag so the default
// `go test ./...` does not pay LLM cost or require a live network.

package llmtest_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/llmtest"
)

const envConfigPath = "TROLLBRIDGE_LLM_TEST_CONFIG"

func TestLLMBundles(t *testing.T) {
	cfgPath := os.Getenv(envConfigPath)
	if cfgPath == "" {
		t.Skipf("%s not set; live-LLM tests skipped. Set %s=/path/to/trollbridge.yaml and re-run with -tags=llmtest.", envConfigPath, envConfigPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load test config %s: %v", cfgPath, err)
	}
	if !cfg.LLM.Enabled {
		t.Fatalf("test config %s must set llm.enabled=true", cfgPath)
	}
	if cfg.LLM.Endpoint == "" {
		t.Fatalf("test config %s must set llm.endpoint", cfgPath)
	}
	apiKey, err := readKeyFile(cfg.LLM.APIKeyPath)
	if err != nil {
		t.Fatalf("read llm.api_key_path %q: %v", cfg.LLM.APIKeyPath, err)
	}
	if apiKey == "" {
		t.Fatalf("llm.api_key_path %q yielded empty key", cfg.LLM.APIKeyPath)
	}

	translator, _ := advisor.TranslatorFor(cfg.LLM.Provider, cfg.LLM.Endpoint)
	if translator == nil {
		t.Fatalf("no translator for provider %q", cfg.LLM.Provider)
	}
	prov := &advisor.HTTPClassifier{
		Endpoint:   cfg.LLM.Endpoint,
		APIKey:     apiKey,
		Translator: translator,
		Model:      cfg.LLM.Model,
	}

	bundles, err := filepath.Glob("bundles/*.yaml")
	if err != nil {
		t.Fatalf("glob bundles: %v", err)
	}
	if len(bundles) == 0 {
		t.Fatal("no bundles found under llmtest/bundles/*.yaml")
	}

	for _, path := range bundles {
		path := path // capture
		t.Run(strings.TrimSuffix(filepath.Base(path), ".yaml"), func(t *testing.T) {
			bundle, err := llmtest.Load(path)
			if err != nil {
				t.Fatalf("load %s: %v", path, err)
			}
			t.Logf("running %s (%s): %d cases", bundle.Name, bundle.Description, len(bundle.Cases))

			// Use a generous per-bundle timeout. Each LLM call has its
			// own translator-level timeout; this is a backstop.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			results := llmtest.Run(ctx, prov, bundle)
			for _, r := range results {
				if r.Pass {
					t.Logf("  PASS  %-40s verdict=%s confidence=%s", r.CaseName, r.Output.Effect, r.Output.Confidence)
					continue
				}
				t.Errorf("  FAIL  %s: %s", r.CaseName, r.Reason)
			}
		})
	}
}

// readKeyFile reads the contents of an llm.api_key_path. trollbridge
// reads keys at startup the same way; we mirror the pattern so the
// framework exercises identical credential plumbing.
func readKeyFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
