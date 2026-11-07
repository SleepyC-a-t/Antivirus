# SentinelGuard 4.2 — experimental Windows desktop security center

SentinelGuard 4.2 combines the manual heuristic scanner and **optional** download
monitoring in one Microsoft Edge WebView2 desktop window. **Live protection,
automatic quarantine and Scan & Run are all OFF on every launch.** It is a
supplement, not a substitute for Microsoft Defender, Bitdefender or the browser's
built-in phishing safeguards.

## Getting started

1. Extract the complete CI archive and open `SentinelGuard-4.2.exe`.
   The Windows 10/11 machine needs the Microsoft Edge WebView2 Runtime.
   This development build is **unsigned**.
2. Manual scan works independently of active protection; you can browse for a
   folder, start a custom or full scan, inspect findings and export a JSON report.
3. Turn live protection ON only when you want newly completed files in
   `Downloads` (or additional user-selected folders) examined. It uses
   **FindFirstChangeNotificationW** and **FindNextChangeNotification**, plus
   periodic directory reconciliation. It does **not** use a
   ReadDirectoryChangesW event buffer or block execution before an app starts.
4. Auto-quarantine remains a separate OFF-by-default choice. The existing
   heuristic score threshold is unchanged at 110; do not mistake a high score
   for proof of malware.
5. Optional **Scan & Run** requires both live monitoring and the independent
   launch-review toggle. Select a local EXE, review SHA-256, file size, Windows
   Authenticode status, publisher when available, Mark-of-the-Web zone and
   contextual findings, and decide whether to start it.
6. The program uses the Windows **ShellExecuteExW "open"** launch pathway,
   allowing applicable Windows shell / Attachment Execution Services / SmartScreen
   dialogs to appear. It holds a read-only, no-write/no-delete sharing file
   handle during final digest verification until ShellExecuteExW returns.
   The file might nevertheless be changed through unusual filesystem mechanisms;
   this is not an absolute race-free execution guarantee.
7. If Windows asks for UAC elevation, **do not approve it for untrusted files**.
   SentinelGuard does not request the "runas" verb. Windows' own requested
   elevation is outside SentinelGuard's complete control; the application
   cannot guarantee every launch is non-elevated. The helper does **not**
   intercept programs launched through Explorer or elsewhere.

## Browser protection (optional)

Two unsigned/unpublished extensions are included:
- Chrome / Edge: load `browser-extension/` with Developer Mode / Load unpacked.
- Firefox: choose `browser-extension-firefox/manifest.json` using
  `about:debugging#/runtime/this-firefox` → Load Temporary Add-on.

For permanent distribution, the developer must obtain Firefox
**AMO unlisted-add-on signing** or publish through the **Chrome Web Store**;
enterprise-managed extension installation is another deployment route.
None of these registration/signing procedures have been completed.

To pair, choose **Copy read-only browser pairing link** in SentinelGuard and
paste it into the extension's popup. The extension stores the randomly
generated shared secret locally; on each health check it sends only a fresh
random nonce to `http://127.0.0.1:17654`. The application replies with an
HMAC-SHA256; the extension verifies it before trusting the app's ON/OFF state.
The secret is **never sent to an unverified local process** on startup.
The user's encrypted pairing secret is persisted with Windows user-scoped DPAPI
in `%LOCALAPPDATA%\SentinelLite\browser-pair.dpapi` and normally survives
restart. **Revoke browser pairing** invalidates the old secret; re-pair
extensions after revocation. A conflicting process holding port 17654 causes a
visible startup failure, not silent fallback.

Opt into the OpenPhish Community Feed in the extension only if you accept its
personal/noncommercial-use terms and IP-address disclosure. The extension
blocks **exact feed URLs** using browser-native declarativeNetRequest rules.
Feed entries containing `*`, `^` or `|` are skipped and counted, since
those are special urlFilter operators. It does **not** upload browser history,
cookies, visited URLs or downloaded files to the feed or SentinelGuard.
The feed's limitations and sync delay mean this is NOT broad web protection.
Keep Firefox/Chrome/Edge built-in Safe Browsing / SmartScreen enabled.

## 4.2 inspection improvements and constraints

- ZIP and nested ZIP scanning recognizes the harmless standardized EICAR
  marker in files of any extension, within strict archive budgets.
- Limited static PE inspection combines imported API patterns with section
  entropy and overlay; **entropy alone never makes a finding**. Trusted
  Authenticode context reduces a corroborated PE score but does not guarantee
  safety.
- Limited binary .lnk, Office OOXML macro, and PDF launch/JavaScript parsing
  includes benign lookalike regression tests.
- Partial downloads (.crdownload/.part) are not scanned until completed/renamed.
  More than 64 simultaneously settled files are queued for further inspection
  instead of being silently marked processed.
- A complete, honest file-type coverage matrix is in
  `docs/SentinelGuard-4.2-COVERAGE.md` in the repository.
- No real-malware dynamic sandbox, memory scanning, OS kernel interception,
  reliable system-wide execution interception, encrypted ZIP/RAR/7z
  unpacking, or unsigned rule-pack update service is implemented.

## Reports and privacy

Full JSON reports can include Windows user names, absolute paths, private
file names, file modified timestamps, SHA-256, and detection reasons.
The **Redact paths and filenames in exported JSON** checkbox creates a
separate share-oriented JSON with salted path/name pseudonyms. It leaves
timestamps, hashes, relevant nonpath reasons and some metadata intact.
**Review redacted reports before public sharing**: masking is best effort.
Active launch audits include timestamp, decision, file path and digest; the
dedicated log is bounded and discloses omitted record counts.

## Testing boundaries

- **CI-tested**: Go unit/regression and race suites, Windows backend launch
  without a GUI, native Windows API test stubs, harmless EICAR and simulated
  controls, and independent static technique samples.
- **Not yet field-tested in 4.2**: interactive WebView2 launch confirmation
  with a real downloaded executable, SmartScreen/MotW prompt sequencing,
  Firefox and Chrome blocking in real browsers, and long-running monitors
  under an end user's workload.
- The former 55/65 Stage 6 and 4/16 Claude-label figures are **development
  regression results**, not real-world malware-detection percentages.
  No genuine malware was downloaded or executed by GitHub Actions.
- No source-code changes alone can provide Authenticode code signing.
  See `docs/SentinelGuard-4.2-RELEASE-SIGNING.md` for a future signing
  workflow and `docs/SentinelGuard-4.2-LAB-RUNBOOK.md` for independently
  run, authorized, offline real-malware evaluation.

**Keep your existing antivirus on. Never override your antivirus's quarantine
or security warnings just to test SentinelGuard.**
