package pattern

import "testing"

func TestAzureKeyVault_Name_Components(t *testing.T) {
	p := AzureKeyVault()
	if p.Name() != "azure_keyvault" {
		t.Fatalf("Name: got %q", p.Name())
	}
	got := p.Components()
	if len(got) != 1 || got[0] != "vault" {
		t.Fatalf("Components: got %v, want [vault]", got)
	}
}

func TestAzureKeyVault_Match(t *testing.T) {
	p := AzureKeyVault()
	cases := []struct {
		name      string
		host      string
		path      string
		wantOK    bool
		wantVault string
	}{
		{name: "happy path", host: "myvault.vault.azure.net", path: "/secrets/MySecret/version1", wantOK: true, wantVault: "myvault"},
		{name: "no path", host: "myvault.vault.azure.net", path: "/", wantOK: true, wantVault: "myvault"},
		{name: "uppercase host lowercased", host: "MYVAULT.VAULT.AZURE.NET", path: "/", wantOK: true, wantVault: "myvault"},
		{name: "non-vault azure subdomain not recognized", host: "myaccount.blob.core.windows.net", path: "/", wantOK: false},
		{name: "deeper subdomain not recognized", host: "sub.foo.vault.azure.net", path: "/", wantOK: false},
		{name: "bare suffix not recognized", host: "vault.azure.net", path: "/", wantOK: false},
		{name: "completely unrelated host", host: "api.github.com", path: "/secrets/x", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, ok := p.Match(tc.host, 443, "https", tc.path)
			if ok != tc.wantOK {
				t.Fatalf("Match ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if res.Components["vault"] != tc.wantVault {
				t.Fatalf("Components[vault] = %q, want %q", res.Components["vault"], tc.wantVault)
			}
		})
	}
}
