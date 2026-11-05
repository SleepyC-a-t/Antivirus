SENTINELLITE 1.0 — WINDOWS ON-DEMAND MALWARE REVIEW UTILITY
==============================================================

WHAT YOU GET
------------
SentinelLite.exe — A single, self-contained, ~6 MB Windows 10/11 (64-bit)
executable. No Python, .NET installation, account, or installer required.

The app starts a LOCAL web interface in your usual browser. It uses a random
loopback port, a private access token, and only listens at 127.0.0.1. It does
not upload files, send telemetry, or contact any external server. The browser
interface is bundled inside the .exe. Internet access is not required for the
app itself; Microsoft Defender may independently use cloud protection under
your existing Windows settings.

HOW TO USE
----------
1. Copy SentinelLite.exe to a location you trust and double-click it.
2. The interface should open in your default web browser. Leave the .exe
   running while using the interface. Click "Exit application" when done.
3. Choose a scan engine:
   * Fast heuristic: file-name, extension, suspicious paths, common malicious
     script patterns, disguised executables, archive member names, EICAR test
     pattern. Good as an initial triage check. NOT a signature antivirus.
   * Microsoft Defender: starts its installed MpCmdRun antivirus engine using
     custom scans with -DisableRemediation. Only works if Defender is installed,
     usable, and has permission to scan. Can take a long time and does not
     provide granular progress in this app.
4. Choose Quick (user folders + Startup), Full (local drive letters), or
   Custom (paste an absolute path to a file/folder). Start scan.
5. Read each finding's "Review" panel, location, risk reasons, and optionally
   SHA-256. Findings from the heuristic scan can be false positives.
6. Tick ONLY files you believe should be quarantined, click "Quarantine
   selected," and confirm. No silent quarantine is performed by SentinelLite.
7. In "Quarantine", you can restore files or PERMANENTLY DELETE a quarantined
   file. Deletion requires typing DELETE. Restoration requires approval.
8. Save a JSON report if desired. Reports include full local file paths and
   can disclose your Windows username to anyone you share the report with.

QUARANTINE
----------
%LOCALAPPDATA%\SentinelLite\Quarantine

The files are moved and renamed with a .quarantined suffix. Metadata and SHA-256
are stored locally to allow restoration with integrity verification. This is
not an operating-system sandbox or a guarantee that a sophisticated active
malware process has been neutralized. A running malware process may need
separate remediation; persistence registry entries and scheduled tasks are not
removed. Files on a different drive are copied, hash-verified, and deleted
from the original location only after verification. A file that is locked,
in use, protected, inaccessible, or changes while being processed may fail to
quarantine. No system files are silently deleted.

IMPORTANT LIMITATIONS
---------------------
* This is an ON-DEMAND REVIEW TOOL, not a complete antivirus, endpoint agent,
  memory scanner, rootkit detector, real-time protector, or YARA engine.
* No clean scan is proof of a clean system. A file's heuristic score is not a
  reliable measure of whether it is actually infected.
* Does not automatically enumerate Run registry keys, scheduled tasks,
  running-process memory, firmware, or unpack password-protected archives.
* Basic heuristic inspection examines limited initial content of relevant file
  types (scripts, executables, ZIP member names, some document headers) and
  can miss hidden or novel malware. ZIP files are inspected by entry name, not
  fully extracted; 7z/RAR internals are not scanned by the heuristic engine.
* Microsoft documents the -DisableRemediation switch for CUSTOM Defender scans:
  the scan does not apply remediation and the detections appear in CLI output.
  However, Microsoft's separate real-time protection can still act under its
  current system policy. A failed or unavailable Defender command-line scan
  will produce an error, not a clean bill of health. Elevated privileges may
  be necessary depending on the environment.
* For thorough malware detection, keep Microsoft Defender or another reputable
  antivirus updated. After a serious infection, consider Microsoft's offline
  scan and specialist assistance.
* The .exe is built for Windows on a Linux machine and was checked as a valid
  64-bit Windows PE executable. Core unit tests passed on Linux, but the GUI,
  Windows Defender integration, and file operations have NOT been validated
  on a real Windows machine in this environment. Use cautiously; backup
  important data first. The binary is not code-signed, so Windows SmartScreen
  might warn that the publisher is unknown. Do not bypass an antivirus
  malware detection just to launch it.

PRIVACY AND SECURITY
--------------------
* The tool never scans anything until you click Start scan.
* It does not download or update signatures on its own.
* The local interface requires an unguessable access token and accepts only
  requests from the local machine.
* It does not make arbitrary outbound web requests.
* There is NO autorun service, scheduled task, startup entry or driver.

BUILD FROM SOURCE
-----------------
Go 1.23 or later recommended. From the src directory:
    go test ./...
    set GOOS=windows
    set GOARCH=amd64
    go build -trimpath -ldflags="-s -w -H windowsgui" -o SentinelLite.exe .

On Linux/macOS, cross-compile with:
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
      -ldflags='-s -w -H windowsgui' -o SentinelLite.exe .

OPTIONAL MICROSOFT DOCUMENTATION
--------------------------------
https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
https://learn.microsoft.com/en-us/defender-endpoint/run-scan-microsoft-defender-antivirus

VERSION: 1.0; educational lightweight on-demand security utility.
