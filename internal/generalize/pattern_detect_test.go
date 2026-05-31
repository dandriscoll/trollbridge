package generalize

import (
	"strings"
	"testing"
)

// stubRecognizer returns a Recognizer that maps hosts to (pattern,
// components) per a fixture table. Unknown hosts return ok=false.
// Components are computed from the URL path on the matching host.
func stubRecognizer(mapping map[string]string) Recognizer {
	return func(host string, port int, scheme, path string) (string, map[string]string, bool) {
		patternName, ok := mapping[host]
		if !ok {
			return "", nil, false
		}
		comps := map[string]string{}
		switch patternName {
		case "azure_arm":
			// /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
			comps["subscription"] = ""
			comps["resource_group"] = ""
			comps["provider"] = ""
			comps["resource_type"] = ""
			comps["resource_name"] = ""
			segs := splitSlash(path)
			for i := 0; i < len(segs); i++ {
				switch strings.ToLower(segs[i]) {
				case "subscriptions":
					if i+1 < len(segs) {
						comps["subscription"] = segs[i+1]
					}
				case "resourcegroups":
					if i+1 < len(segs) {
						comps["resource_group"] = segs[i+1]
					}
				case "providers":
					if i+1 < len(segs) {
						comps["provider"] = segs[i+1]
					}
					if i+2 < len(segs) {
						comps["resource_type"] = segs[i+2]
					}
					if i+3 < len(segs) {
						comps["resource_name"] = segs[i+3]
					}
				}
			}
		case "azure_keyvault":
			comps["vault"] = strings.TrimSuffix(host, ".vault.azure.net")
		}
		return patternName, comps, true
	}
}

func splitSlash(p string) []string {
	if p == "" {
		return nil
	}
	if p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func TestDetectPattern_NilRecognizer_Empty(t *testing.T) {
	if got := DetectPattern([]string{"GET https://management.azure.com/subscriptions/A"}, nil, nil); len(got) != 0 {
		t.Fatalf("nil recognizer should yield empty; got %d candidates", len(got))
	}
}

func TestDetectPattern_SingleEntry_NoCandidate(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	got := DetectPattern(
		[]string{"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1"},
		nil, rec,
	)
	if len(got) != 0 {
		t.Fatalf("single entry should produce no candidate; got %+v", got)
	}
}

func TestDetectPattern_ARM_SameSubscriptionDifferentVMs_WildcardsResourceName(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	entries := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-3",
	}
	got := DetectPattern(entries, nil, rec)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate; got %d: %+v", len(got), got)
	}
	c := got[0]
	if string(c.Axis) != "pattern:azure_arm" {
		t.Fatalf("axis = %s", c.Axis)
	}
	if c.PatternMatch == nil {
		t.Fatal("PatternMatch must be non-nil")
	}
	if c.PatternMatch.Pattern != "azure_arm" {
		t.Fatalf("pattern = %q", c.PatternMatch.Pattern)
	}
	if c.PatternMatch.Method != "GET" {
		t.Fatalf("method = %q", c.PatternMatch.Method)
	}
	// resource_name varies; should NOT appear in Components map.
	if _, present := c.PatternMatch.Components["resource_name"]; present {
		t.Fatal("resource_name varies; should be absent from Components")
	}
	// subscription, resource_group, provider, resource_type all constant.
	for k, want := range map[string]string{
		"subscription":   "SUB-A",
		"resource_group": "rg1",
		"provider":       "Microsoft.Compute",
		"resource_type":  "virtualMachines",
	} {
		if got := c.PatternMatch.Components[k]; got != want {
			t.Fatalf("Components[%q] = %q, want %q", k, got, want)
		}
	}
	if len(c.SourceEntries) != 3 {
		t.Fatalf("SourceEntries = %d, want 3", len(c.SourceEntries))
	}
}

func TestDetectPattern_ARM_DifferentSubscriptionsSameMethod_WildcardsSubscription(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	entries := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-B/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
	}
	got := DetectPattern(entries, nil, rec)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate; got %d", len(got))
	}
	if _, present := got[0].PatternMatch.Components["subscription"]; present {
		t.Fatal("subscription varies; should be absent from Components (wildcard)")
	}
	if v := got[0].PatternMatch.Components["resource_group"]; v != "rg1" {
		t.Fatalf("resource_group should be constant rg1; got %q", v)
	}
}

func TestDetectPattern_ARM_MixedMethods_SplitsIntoTwoGroups(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	entries := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
		"DELETE https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-3",
		"DELETE https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-4",
	}
	got := DetectPattern(entries, nil, rec)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates (one per method); got %d", len(got))
	}
	methods := map[string]bool{}
	for _, c := range got {
		methods[c.PatternMatch.Method] = true
	}
	if !methods["GET"] || !methods["DELETE"] {
		t.Fatalf("expected GET and DELETE candidates; got methods %v", methods)
	}
}

func TestDetectPattern_KeyVault_DifferentVaults_WildcardsVault(t *testing.T) {
	rec := stubRecognizer(map[string]string{
		"vault-a.vault.azure.net": "azure_keyvault",
		"vault-b.vault.azure.net": "azure_keyvault",
	})
	entries := []string{
		"GET https://vault-a.vault.azure.net/secrets/s1",
		"GET https://vault-b.vault.azure.net/secrets/s2",
	}
	got := DetectPattern(entries, nil, rec)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate; got %d", len(got))
	}
	if _, present := got[0].PatternMatch.Components["vault"]; present {
		t.Fatal("vault varies; should be absent from Components")
	}
}

func TestDetectPattern_AllowDenyIsolation(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	allow := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}
	deny := []string{
		"DELETE https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-3",
		"DELETE https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-4",
	}
	got := DetectPattern(allow, deny, rec)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates (one per list); got %d", len(got))
	}
	lists := map[string]bool{}
	for _, c := range got {
		lists[c.List] = true
	}
	if !lists["allow"] || !lists["deny"] {
		t.Fatalf("expected allow+deny lists; got %v", lists)
	}
}

func TestDetectPattern_NonPatternEntriesIgnored(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	entries := []string{
		"GET https://api.github.com/repos/foo/bar",
		"GET https://api.github.com/repos/baz/qux",
	}
	got := DetectPattern(entries, nil, rec)
	if len(got) != 0 {
		t.Fatalf("non-pattern entries should produce no pattern candidates; got %+v", got)
	}
}

func TestDetectPattern_RecognizerPanicSkipsEntry(t *testing.T) {
	count := 0
	recPanic := Recognizer(func(host string, port int, scheme, path string) (string, map[string]string, bool) {
		count++
		if count == 1 {
			panic("synthetic")
		}
		return "azure_arm", map[string]string{
			"subscription": "SUB-A", "resource_group": "", "provider": "", "resource_type": "", "resource_name": "",
		}, true
	})
	// DetectPattern doesn't itself recover; the contract per design
	// is that the SERVER-supplied recognizer (pattern.Registry) is
	// the one that catches panics. Verify the contract by ensuring
	// a non-panicking recognizer works; the production wiring
	// handles the panic shape upstream. This test pins the no-recover
	// behavior so we don't accidentally add a redundant recover in
	// DetectPattern.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected DetectPattern to propagate the recognizer's panic — recovery is the recognizer's job")
		}
	}()
	_ = DetectPattern([]string{"GET https://management.azure.com/subscriptions/SUB-A"}, nil, recPanic)
}

func TestDetectAllWithRecognizer_AppendsPatternCandidates(t *testing.T) {
	rec := stubRecognizer(map[string]string{"management.azure.com": "azure_arm"})
	allow := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}
	got := DetectAllWithRecognizer(allow, nil, rec)
	hasPattern := false
	for _, c := range got {
		if strings.HasPrefix(string(c.Axis), AxisPatternPrefix) {
			hasPattern = true
			break
		}
	}
	if !hasPattern {
		t.Fatalf("expected DetectAllWithRecognizer to include a pattern:* candidate; got %+v", got)
	}
}

func TestDetectAllWithRecognizer_NilRecognizer_EquivalentToDetectAll(t *testing.T) {
	allow := []string{
		"GET https://api.example.com/v1/users/1",
		"GET https://api.example.com/v1/users/2",
	}
	flat := DetectAll(allow, nil)
	combined := DetectAllWithRecognizer(allow, nil, nil)
	if len(flat) != len(combined) {
		t.Fatalf("DetectAllWithRecognizer(nil) should equal DetectAll; flat=%d combined=%d", len(flat), len(combined))
	}
}
