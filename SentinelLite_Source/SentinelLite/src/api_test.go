package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalAPIQuarantineReviewFlow(t *testing.T) {
	base := t.TempDir()
	q := filepath.Join(base, "quarantine")
	if err := os.MkdirAll(q, 0700); err != nil {
		t.Fatal(err)
	}
	scanDir := filepath.Join(base, "samples")
	if err := os.Mkdir(scanDir, 0700); err != nil {
		t.Fatal(err)
	}
	sample := filepath.Join(scanDir, "urgent.pdf.exe")
	_ = os.WriteFile(sample, []byte("not malware; just a filename test"), 0600)
	app := newApp(&Vault{path: q})
	srv := httptest.NewUnstartedServer(nil)
	server := &Server{app: app, token: "test-token", address: srv.Listener.Addr().String()}
	srv.Config.Handler = server.routes()
	srv.Start()
	defer srv.Close()
	request := func(method, route string, data any, authorized bool) (int, map[string]any) {
		t.Helper()
		var body []byte
		if data != nil {
			body, _ = json.Marshal(data)
		}
		req, err := http.NewRequest(method, srv.URL+route, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if authorized {
			req.Header.Set("X-Sentinel-Token", "test-token")
		}
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}
	status, _ := request("GET", "/api/snapshot", nil, false)
	if status != 403 {
		t.Fatalf("invalid-token request permitted: %d", status)
	}
	status, result := request("POST", "/api/start", map[string]any{"engine": "heuristic", "mode": "custom", "path": scanDir}, true)
	if status != 200 {
		t.Fatalf("scan start: %d %+v", status, result)
	}
	deadline := time.After(4 * time.Second)
	var fileID string
	for {
		_, r := request("GET", "/api/snapshot", nil, true)
		st := r["status"].(map[string]any)
		if !st["active"].(bool) {
			fs := r["findings"].([]any)
			if len(fs) != 1 {
				t.Fatalf("wanted one finding, got %+v", fs)
			}
			f := fs[0].(map[string]any)
			fileID = f["id"].(string)
			break
		}
		select {
		case <-deadline:
			t.Fatal("scanner never completed")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	status, _ = request("POST", "/api/quarantine", map[string]any{"IDs": []string{fileID}, "Confirm": false}, true)
	if status != 400 {
		t.Fatalf("quarantine accepted without confirmation: %d", status)
	}
	status, r := request("POST", "/api/quarantine", map[string]any{"IDs": []string{fileID}, "Confirm": true}, true)
	if status != 200 {
		t.Fatalf("quarantine failed %d %+v", status, r)
	}
	if _, err := os.Stat(sample); !os.IsNotExist(err) {
		t.Fatalf("sample not moved, err=%v", err)
	}
	_, r = request("GET", "/api/vault", nil, true)
	items := r["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("quarantine empty %+v", r)
	}
	id := items[0].(map[string]any)["id"].(string)
	status, _ = request("POST", "/api/vault-action", map[string]any{"ID": id, "Action": "restore", "Confirm": true}, true)
	if status != 200 {
		t.Fatalf("restore failed: %d", status)
	}
	if _, err := os.Stat(sample); err != nil {
		t.Fatalf("sample not restored: %v", err)
	}
}
