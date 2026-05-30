package pattern

import (
	"strings"
)

// azureARM recognizes URLs against management.azure.com — the
// Azure Resource Manager control plane.
//
// Canonical ARM URL shape:
//
//	/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/{provider}/{resource_type}/{resource_name}[/...]
//
// Variants also recognized:
//
//	/subscriptions/{subscription}/resourcegroups/...  (case-insensitive path keyword)
//	/subscriptions/{subscription}/providers/{provider}/{resource_type}/{resource_name}     (subscription-scoped, no RG)
//	/subscriptions/{subscription}                                                          (subscription-list-like)
//	/providers/{provider}[/{resource_type}[/{resource_name}]]                              (tenant-scoped, no subscription)
//
// Sub-actions (/start, /restart, /listKeys) and child resources
// (extensions/<name>) past the top-level resource name are
// ignored for v1 — the path tail beyond the parent's name is not
// extracted as a component. Filed for future expansion.
//
// Query strings (?api-version=...) are stripped by the matcher;
// they do not affect recognition.
type azureARM struct{}

// AzureARM returns the built-in ARM pattern. Stateless singleton.
func AzureARM() Pattern { return azureARM{} }

const (
	armComponentSubscription = "subscription"
	armComponentResourceGroup = "resource_group"
	armComponentProvider      = "provider"
	armComponentResourceType  = "resource_type"
	armComponentResourceName  = "resource_name"
)

func (azureARM) Name() string { return "azure_arm" }

func (azureARM) Components() []string {
	return []string{
		armComponentSubscription,
		armComponentResourceGroup,
		armComponentProvider,
		armComponentResourceType,
		armComponentResourceName,
	}
}

func (a azureARM) Match(host string, _ int, _, path string) (MatchResult, bool) {
	if !strings.EqualFold(host, "management.azure.com") {
		return MatchResult{}, false
	}
	// Strip a query/fragment if it slipped in.
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == "/" {
		return MatchResult{}, false
	}
	segs := splitPath(path)
	if len(segs) == 0 {
		return MatchResult{}, false
	}
	// Initialize all components to empty so the contract holds:
	// when we return true, every declared component name is
	// present.
	comps := map[string]string{
		armComponentSubscription:  "",
		armComponentResourceGroup: "",
		armComponentProvider:      "",
		armComponentResourceType:  "",
		armComponentResourceName:  "",
	}
	switch strings.ToLower(segs[0]) {
	case "subscriptions":
		// /subscriptions/{sub}[...]
		if len(segs) < 2 {
			return MatchResult{}, false
		}
		comps[armComponentSubscription] = segs[1]
		// Walk further: optional resourceGroups + providers.
		i := 2
		for i < len(segs) {
			kw := strings.ToLower(segs[i])
			switch kw {
			case "resourcegroups":
				if i+1 >= len(segs) {
					i++
					continue
				}
				comps[armComponentResourceGroup] = segs[i+1]
				i += 2
			case "providers":
				// providers/{namespace}/{type}/{name}[/...]
				if i+1 < len(segs) {
					comps[armComponentProvider] = segs[i+1]
				}
				if i+2 < len(segs) {
					comps[armComponentResourceType] = segs[i+2]
				}
				if i+3 < len(segs) {
					comps[armComponentResourceName] = segs[i+3]
				}
				// v1 stops after the top-level resource name;
				// child resources and sub-actions are out of scope.
				return MatchResult{Components: comps}, true
			default:
				// Unknown keyword — stop walking, recognize what
				// we have so far. Recognition is robust to
				// surface evolution; rule eval just won't match
				// uninitialized components.
				return MatchResult{Components: comps}, true
			}
		}
		return MatchResult{Components: comps}, true
	case "providers":
		// Tenant-scoped: /providers/{ns}/{type}/{name}[/...]
		if len(segs) >= 2 {
			comps[armComponentProvider] = segs[1]
		}
		if len(segs) >= 3 {
			comps[armComponentResourceType] = segs[2]
		}
		if len(segs) >= 4 {
			comps[armComponentResourceName] = segs[3]
		}
		return MatchResult{Components: comps}, true
	default:
		// Not a recognizable ARM root segment.
		return MatchResult{}, false
	}
}

// splitPath splits "/a/b/c" into ["a","b","c"]. Empty path,
// "/", and paths with consecutive slashes ("/a//b") yield
// short results — callers must check len() before indexing.
// Trailing slash is ignored.
func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	if p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return nil
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
