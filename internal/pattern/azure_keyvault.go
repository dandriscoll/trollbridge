package pattern

import "strings"

// azureKeyVault recognizes Azure Key Vault URLs (the data plane,
// served at *.vault.azure.net).
//
// Component model (v1 — host-level only, per the brief):
//
//	vault — the vault name (the subdomain prefix of vault.azure.net)
//
// The path is not decomposed in v1; the brief explicitly scopes
// Key Vault as host-level matching. Per-object/per-version
// extraction (/secrets/{name}/{version}, /keys/{name}, etc.) is
// deferred to a follow-up.
type azureKeyVault struct{}

// AzureKeyVault returns the built-in Key Vault pattern. Stateless
// singleton.
func AzureKeyVault() Pattern { return azureKeyVault{} }

const (
	keyvaultComponentVault = "vault"
	keyvaultHostSuffix     = ".vault.azure.net"
)

func (azureKeyVault) Name() string { return "azure_keyvault" }

func (azureKeyVault) Components() []string {
	return []string{keyvaultComponentVault}
}

func (azureKeyVault) Match(host string, _ int, _, _ string) (MatchResult, bool) {
	h := strings.ToLower(host)
	if !strings.HasSuffix(h, keyvaultHostSuffix) {
		return MatchResult{}, false
	}
	vault := strings.TrimSuffix(h, keyvaultHostSuffix)
	if vault == "" || strings.Contains(vault, ".") {
		// "vault.azure.net" itself, or a deeper subdomain like
		// "foo.bar.vault.azure.net", is not a Key Vault data-plane
		// URL — vaults are exactly one label deep below the suffix.
		return MatchResult{}, false
	}
	return MatchResult{
		Components: map[string]string{keyvaultComponentVault: vault},
	}, true
}
