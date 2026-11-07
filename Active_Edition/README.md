# SentinelGuard 4.1 — integrated Windows desktop security center

SentinelGuard 4.1 combines the existing manual scanner and its experimental
opt-in Active monitor into **one Windows desktop application**. The dashboard
runs inside a native Windows WebView2 window (Microsoft Edge WebView2 Runtime)
rather than a tab in Firefox, Chrome or Edge.

## Starting SentinelGuard

1. Extract the full ZIP.
2. Start `SentinelGuard-4.1.exe`. No separate server, browser or Python is
   needed on your Windows PC. Windows 10/11 must have Microsoft Edge WebView2
   Runtime installed.
3. **Live protection is OFF by default on EVERY launch.** Manual scans,
   scanned-file counts, findings, detailed skipped paths, quarantine vault and
   process CPU/RAM telemetry still work independently.
4. To try live monitoring, choose **Turn protection ON** in the app. If
   `Downloads` is found it is watched automatically; choose **Add folder…**
   to include other download destinations. Existing files are baselined when
   monitoring is enabled. New or changed files are inspected after their writes
   have settled, generally several seconds after a browser finishes saving.
5. The independent **Allow auto-quarantine** checkbox also defaults OFF.
   Opting in permits auto-quarantine only for findings scoring at least 110;
   lower scores are always reviewed instead of moved automatically.
6. The protection switch and entire monitor stop working when the application
   exits or protection is turned OFF. This is not a Windows service and does not
   automatically start after reboot.

## Browser website protection (optional)

The browser companion uses a read-only local status pairing key plus
`declarativeNetRequest` to block exact known phishing URLs from the optional
OpenPhish Community Feed. Installing the extension is optional; it is not
required for local file scanning.

- **Firefox:** open `about:debugging#/runtime/this-firefox` > Load Temporary
  Add-on, select `browser-extension-firefox/manifest.json`. The extension is
  temporary until signed by Mozilla.
- **Chrome/Edge:** open the extensions page, enable Developer mode, choose
  Load unpacked, and select `browser-extension`.
- From the SentinelGuard app click **Copy read-only browser pairing link**,
  paste the link into your extension popup and choose Pair/update.
- In the extension popup enable the **OpenPhish Community Feed** checkbox
  if you agree to the feed provider's terms and IP-address disclosure.
- Blocking state can take up to about a minute to reflect changes to the
  application's protection switch. Pairing must be renewed after restarting
  the application because the secure local port/key changes per launch.

The feed's terms restrict community-feed use to personal/noncommercial
use. No website contents, passwords, history or files you download are
uploaded by SentinelGuard. The extension requests the feed from OpenPhish
if and only if opted in, revealing your IP address to that provider.

## Limits and transparency

This is an **experimental supplement** to proper real-time antivirus,
not an OS-level protection system. It does not install a kernel
file-filter driver, intercept TLS or inspect memory/process events.
Folder monitoring is not a pre-execution block: an untrusted file may be
opened before the monitor inspects it. It only monitors configured directories,
not every possible browser download folder, USB drive or cloud location.

The application still uses the Stage 12 static heuristic engine, which
found 55/65 synthetic suspicious cases with zero false positives among 30
Stage 6 benign controls, but recognized only 4 of 16 Claude-labeled inert
"suspicious" artifacts (0 of 8 benign controls incorrectly flagged).
Many of the inert artifacts are intentionally harmless demonstrations.

Windows Defender / Bitdefender and your browser's standard protection should
stay enabled. The executable is unsigned and may be flagged as an unknown
publisher. Do not bypass an antivirus block just to run experimental code.

**Privacy:** Exported JSON reports and local log files can contain Windows
usernames, filenames, directory paths, timestamps and finding reasons.
Redact these before sharing publicly.

**Development:** Python is used only by CI to regenerate Claude's inert
test fixtures in a temporary directory. No Python interpreter or test
corpus is included in the production application.

## SentinelGuard 4.1 security options and privacy

**Priority 1 — browser URL blocking:** The optional Firefox/Chrome/Edge
extension uses anchored literal URL filters rather than regex rules; this
avoids the Chrome 1,000-regex-rule cap. An update error keeps working
rules when possible and reports degraded status. When protection is OFF,
the extension removes its blocking rules at the next synchronization.

**Persistent pairing:** On Windows, the browser pairing credential is
encrypted using the user-account-scoped Windows DPAPI and stored under
`%LOCALAPPDATA%\SentinelLite\browser-pair.dpapi`. The browser extension
keeps its token in browser extension storage. The API listens only on
`127.0.0.1:17654`, so the extension can reconnect after restarting
SentinelGuard. Use **Revoke browser pairing** to invalidate existing
extensions. If the port is already occupied, close the conflicting app.

**Priority 2 — downloads:** Windows change notifications now wake the
monitor; a periodic folder reconciliation covers missed notifications.
Each completed file inspection, including clean/no-indicator files, is
recorded in Recent protection events and export JSON. The events may
contain your private filenames and folder paths.

**Priority 3 — optional Scan & Run:** Separate opt-in switch, OFF by
default. Select a local `.exe` in the Windows picker, inspect the file,
then approve or cancel the launch in a confirmation dialog. An approval
ticket expires after 90 seconds, is usable once, and is bound to the
executable's SHA-256 and size. The app checks the file again before
starting it; a change requires a new review. A residual check-to-execution
race remains possible. No system-wide execution interception, driver,
Windows policy modification, network executable, scripts or shortcuts.
Programs launched using Explorer or other applications do not pass
through this prompt. SentinelGuard does not guarantee an executable safe.

**Priority 4 — validation:** The exact Claude inert sample corpus is
generated only in isolated CI tests, never executed. Original Stage
6–12 synthetic test matrices remain. We also scan installed Windows
system executables as real benign controls (without launching them).
EICAR checks test a standard harmless antivirus test signature; they
do not establish independent detection rates against real malware.
Use established primary antivirus and Windows security features.

New Scan & Run events include selected program path, timestamp, heuristic
score, whether the user declined or approved, execution failures and
file-change/expiry denials. Turning on active scanning does NOT enable
Scan & Run or auto-quarantine; both are separately OFF by default.
