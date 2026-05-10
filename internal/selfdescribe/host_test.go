package selfdescribe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestIsMagicHost_AbsoluteURL(t *testing.T) {
	r := httptest.NewRequest("GET", "http://config.trollbridge.dev/setup/ca.crt", nil)
	if !IsMagicHost(r) {
		t.Errorf("absolute-URL form not recognized: r.URL.Host=%q r.Host=%q", r.URL.Host, r.Host)
	}
}

func TestIsMagicHost_HostHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/setup/ca.crt", nil)
	r.URL.Host = ""
	r.Host = "config.trollbridge.dev"
	if !IsMagicHost(r) {
		t.Errorf("host-header form not recognized")
	}
}

func TestIsMagicHost_PortStripped(t *testing.T) {
	r := httptest.NewRequest("GET", "http://config.trollbridge.dev:8080/setup/ca.crt", nil)
	if !IsMagicHost(r) {
		t.Errorf("port suffix prevented match")
	}
}

func TestIsMagicHost_CaseInsensitive(t *testing.T) {
	r := httptest.NewRequest("GET", "http://Config.Trollbridge.Dev/setup", nil)
	if !IsMagicHost(r) {
		t.Errorf("mixed-case host not recognized")
	}
}

func TestIsMagicHost_NotMatch(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/foo", nil)
	if IsMagicHost(r) {
		t.Errorf("non-magic host matched: %q", r.URL.Host)
	}
}

func TestIsMagicHost_EmptyHostFalse(t *testing.T) {
	r := &http.Request{URL: &url.URL{}}
	if IsMagicHost(r) {
		t.Errorf("empty host should not match")
	}
}
