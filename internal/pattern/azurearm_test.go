package pattern

import (
	"sort"
	"testing"
)

func TestAzureARM_Name_Components(t *testing.T) {
	p := AzureARM()
	if p.Name() != "azure_arm" {
		t.Fatalf("Name: got %q, want azure_arm", p.Name())
	}
	got := append([]string(nil), p.Components()...)
	sort.Strings(got)
	want := []string{"provider", "resource_group", "resource_name", "resource_type", "subscription"}
	if len(got) != len(want) {
		t.Fatalf("Components: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("Components[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAzureARM_Match(t *testing.T) {
	p := AzureARM()
	type comp = map[string]string
	cases := []struct {
		name     string
		host     string
		path     string
		wantOK   bool
		wantComp comp
	}{
		{
			name:   "full ARM resource URL",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "ARM URL with query string",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1?api-version=2023-01-01",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "lowercase resourcegroups keyword still recognized",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourcegroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "ARM URL with sub-action (/start) extracts parent resource",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1/start",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "child resource (extensions) extracts parent only in v1",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1/extensions/ext-1",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "subscription-scoped, no resource group",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/providers/Microsoft.Authorization/roleAssignments/role-1",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "",
				"provider":       "Microsoft.Authorization",
				"resource_type":  "roleAssignments",
				"resource_name":  "role-1",
			},
		},
		{
			name:   "subscription only (listing call)",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "",
				"provider":       "",
				"resource_type":  "",
				"resource_name":  "",
			},
		},
		{
			name:   "tenant-scoped /providers/... (no subscription)",
			host:   "management.azure.com",
			path:   "/providers/Microsoft.ResourceGraph/resources",
			wantOK: true,
			wantComp: comp{
				"subscription":   "",
				"resource_group": "",
				"provider":       "Microsoft.ResourceGraph",
				"resource_type":  "resources",
				"resource_name":  "",
			},
		},
		{
			name:   "empty subscription segment (operator typo) yields empty subscription",
			host:   "management.azure.com",
			path:   "/subscriptions//resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
			wantOK: true,
			wantComp: comp{
				"subscription":   "",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
		{
			name:   "case-insensitive host (uppercase)",
			host:   "MANAGEMENT.AZURE.COM",
			path:   "/subscriptions/SUB-A/providers/Microsoft.Authorization/roleAssignments/r",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "",
				"provider":       "Microsoft.Authorization",
				"resource_type":  "roleAssignments",
				"resource_name":  "r",
			},
		},
		{
			name:   "wrong host is not recognized",
			host:   "api.github.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
			wantOK: false,
		},
		{
			name:   "empty path is not recognized",
			host:   "management.azure.com",
			path:   "",
			wantOK: false,
		},
		{
			name:   "root path is not recognized",
			host:   "management.azure.com",
			path:   "/",
			wantOK: false,
		},
		{
			name:   "unknown top-level segment is not recognized",
			host:   "management.azure.com",
			path:   "/locations/eastus",
			wantOK: false,
		},
		{
			name:   "trailing slash after resource name still extracts",
			host:   "management.azure.com",
			path:   "/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1/",
			wantOK: true,
			wantComp: comp{
				"subscription":   "SUB-A",
				"resource_group": "rg1",
				"provider":       "Microsoft.Compute",
				"resource_type":  "virtualMachines",
				"resource_name":  "vm-1",
			},
		},
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
			for k, v := range tc.wantComp {
				if got := res.Components[k]; got != v {
					t.Fatalf("Components[%q] = %q, want %q", k, got, v)
				}
			}
			// Contract: every declared component name must be a
			// key in the result.
			for _, c := range p.Components() {
				if _, ok := res.Components[c]; !ok {
					t.Fatalf("Components map missing declared component %q", c)
				}
			}
		})
	}
}
