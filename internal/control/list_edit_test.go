package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
)

// stubListWriter captures mutations for assertions. Returns
// changed=true unless overridden, err=nil unless wantErr is set.
type stubListWriter struct {
	mu       sync.Mutex
	addAllow []string
	addDeny  []string
	rmAllow  []string
	rmDeny   []string
	wantErr  error
}

func (s *stubListWriter) AddAllow(p string) (bool, error) {
	if s.wantErr != nil {
		return false, s.wantErr
	}
	s.mu.Lock()
	s.addAllow = append(s.addAllow, p)
	s.mu.Unlock()
	return true, nil
}
func (s *stubListWriter) AddDeny(p string) (bool, error) {
	if s.wantErr != nil {
		return false, s.wantErr
	}
	s.mu.Lock()
	s.addDeny = append(s.addDeny, p)
	s.mu.Unlock()
	return true, nil
}
func (s *stubListWriter) RemoveAllow(p string) (bool, error) {
	if s.wantErr != nil {
		return false, s.wantErr
	}
	s.mu.Lock()
	s.rmAllow = append(s.rmAllow, p)
	s.mu.Unlock()
	return true, nil
}
func (s *stubListWriter) RemoveDeny(p string) (bool, error) {
	if s.wantErr != nil {
		return false, s.wantErr
	}
	s.mu.Lock()
	s.rmDeny = append(s.rmDeny, p)
	s.mu.Unlock()
	return true, nil
}

// TestControl_ListEditAllow_AddsPattern pins the POST /v1/lists/allow
// endpoint (#189): the request body's pattern flows to
// ListWriter.AddAllow; the response carries {"changed": true}.
func TestControl_ListEditAllow_AddsPattern(t *testing.T) {
	srv, addr, caObj, cancel := bootControl(t)
	defer cancel()
	w := &stubListWriter{}
	srv.SetListWriter(w)

	c := clientWithCert(t, caObj, "operator-1")
	body, _ := json.Marshal(map[string]string{"pattern": "host.example/api/*"})
	resp, err := c.Post("https://"+addr+"/v1/lists/allow", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, body=%s", resp.StatusCode, respBody)
	}
	var got struct{ Changed bool }
	jsonDecode(t, resp.Body, &got)
	if !got.Changed {
		t.Errorf("response.changed = false, want true")
	}
	if len(w.addAllow) != 1 || w.addAllow[0] != "host.example/api/*" {
		t.Errorf("AddAllow not called with the right pattern; got %v", w.addAllow)
	}
}

// TestControl_ListEditDeny_RemovesPattern pins the DELETE /v1/lists/deny
// endpoint (#189).
func TestControl_ListEditDeny_RemovesPattern(t *testing.T) {
	srv, addr, caObj, cancel := bootControl(t)
	defer cancel()
	w := &stubListWriter{}
	srv.SetListWriter(w)

	c := clientWithCert(t, caObj, "operator-1")
	body, _ := json.Marshal(map[string]string{"pattern": "evil.example"})
	req, _ := http.NewRequest("DELETE", "https://"+addr+"/v1/lists/deny", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, body=%s", resp.StatusCode, respBody)
	}
	if len(w.rmDeny) != 1 || w.rmDeny[0] != "evil.example" {
		t.Errorf("RemoveDeny not called with the right pattern; got %v", w.rmDeny)
	}
}

// TestControl_ListEdit_NoWriterReturns503 pins that the endpoint
// surfaces a 503 (with a JSON error body) when SetListWriter was
// never called — operator gets a structured error instead of a
// confusing 200.
func TestControl_ListEdit_NoWriterReturns503(t *testing.T) {
	_, addr, caObj, cancel := bootControl(t)
	defer cancel()

	c := clientWithCert(t, caObj, "operator-1")
	body, _ := json.Marshal(map[string]string{"pattern": "x"})
	resp, err := c.Post("https://"+addr+"/v1/lists/allow", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", resp.StatusCode)
	}
}

// TestControl_ListEdit_MissingPatternReturns400 pins the
// validation: an empty pattern is a client error.
func TestControl_ListEdit_MissingPatternReturns400(t *testing.T) {
	srv, addr, caObj, cancel := bootControl(t)
	defer cancel()
	srv.SetListWriter(&stubListWriter{})

	c := clientWithCert(t, caObj, "operator-1")
	body, _ := json.Marshal(map[string]string{"pattern": ""})
	resp, err := c.Post("https://"+addr+"/v1/lists/allow", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

// TestControl_ListEdit_WriterErrorSurfaces500 pins that a writer
// error (disk full, permission denied) bubbles up as a 500 with a
// JSON body — operator can see the proxy's error message.
func TestControl_ListEdit_WriterErrorSurfaces500(t *testing.T) {
	srv, addr, caObj, cancel := bootControl(t)
	defer cancel()
	srv.SetListWriter(&stubListWriter{wantErr: errors.New("disk full")})

	c := clientWithCert(t, caObj, "operator-1")
	body, _ := json.Marshal(map[string]string{"pattern": "host.example"})
	resp, err := c.Post("https://"+addr+"/v1/lists/allow", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", resp.StatusCode)
	}
}

func jsonDecode(t *testing.T, r io.Reader, v any) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
