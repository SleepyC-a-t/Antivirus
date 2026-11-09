# SentinelGuard 4.2 — CI validation report (draft)

**Source:** GitHub Actions runs on 2026-11-07: Windows desktop `42398762460` (failed at legacy UI branding assertions), benign / public technique `42398762471` (passed), browser companion `42398762462` (passed). All counts below refer to these precise runs, not an untested later commit. Re-run before release.

## Regression locks (not detection measurements)
- Stage 6: 55/65 suspicious-labeled fixtures found, 10 missed, 0/30 controls flagged. Samples are developer fixtures, many containing inert textual indicators and not independently labeled malware.
- Stage 9: 35/35 flagged, 0/37 controls flagged. Regression lock.
- Stage 10, Stage 11, EICAR synthetic ZIP recursion, malicious/benign structured-analyzer unit tests: passed in the Windows log, but do **not** represent general-world sensitivity.
- Windows `go test -race` was not performed; Linux race-validation job passed. Windows test jobs were run, but the Windows desktop build **did not finish** in run `42398762460`.

## Frozen benign holdout (not sensitivity)
- Predeclared subset of expected-benign Windows executables: 0/19 flagged; Wilson 95% flag-rate interval 0–16.8179%. Overlaps previously used Windows files, so not fully independent. No real-world malicious holdout exists. **Do not report a malware-detection confidence interval.**

## Real expected-benign files, Windows CI
*Predeclared scanner roots and caps; not a randomized population sample. Flags are triage candidates, not confirmed false positives without review.*

| Root | Inspected | Flagged |
|---|---:|---:|
| C:\\Windows\\System32 | 2,198 | 1 |
| C:\\Windows\\SysWOW64 | 1,200 | 0 |
| Program Files | 1,800 | 0 |
| Program Files (x86) | 989 | 0 |
| Python standard library and documentation | 800 | 4 |
| Global npm packages | 800 | 0 |
| **Total** | **7,787** | **5** |

Overall flag proportion = 5/7,787 = 0.0642%; Wilson 95% interval = 0.0274%–0.1502%, **conditional on this sampled corpus**.

Flagged files and reasons:
1. `Windows/System32/BestPractices/v1.0/Models/Microsoft/Windows/TerminalServices/TerminalServices.ps1` — score 43, dynamically constructed DNS lookup.
2. `Python/3.12.10/Doc/html/library/crypt.html` — score 40, remote-destination password form.
3. `Python/3.12.10/Doc/html/library/getpass.html` — same.
4. `Python/3.12.10/Doc/html/library/pwd.html` — same.
5. `Python/3.12.10/Doc/html/library/spwd.html` — same.

The 4.1 baseline survey in the comparison workflow also reported 5/7,787 flagged on that runner. No demonstrated false-positive improvement. The original Windows full test workflow without Python/npm root variables recorded 1/6,187; **do not compare these unlike sampling frames**.

## Public independent technique materials (read-only)
- Official vendor `eicar_com.zip`: SHA-256 `2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad`, detected=true. Official `eicarcom2.zip` unavailable, not evaluated by vendor bytes. Reconstructed nested ZIP marker tests passed.
- 4 independent static definition files (Atomic Red Team definitions, LOLBAS command definitions, Microsoft harmless AMSI demonstration): 2 flagged. No positive/negative malware labels assigned; **2/4 is not a detection-rate claim**.
- AMTSO PUA is not a required detection for a signature-free engine; do not count failure against broad real-world precision/sensitivity. No special PUA test-sample hash added.

## Not tested / release blockers
- No real-malware corpus or in-the-wild holdout, no malware execution and no sandbox.
- No interactive WebView2 Windows Scan & Run / SmartScreen / UAC sequencing, browser blocking in live browsers, or full sustained user-workload download monitoring.
- No externally obtained code-signing certificate; build remains unsigned.
- Legacy UI branding checks caused the Windows job to fail; latest changes update exact branding expectations without deleting the tests. A newly successful Windows build workflow and SHA-256 artifact are required.

## Ground-rule source verification
(a) `launch_windows.go` uses `ShellExecuteExW` with verb `open` for the 4.2 reviewed path (not `CreateProcess`). A read-only handle with `FILE_SHARE_READ` remains held during the final digest check and Shell dispatch; race is reduced, not eliminated.

(b) `active_notify_windows.go` uses `FindFirstChangeNotificationW` / `FindNextChangeNotification`, **not** `ReadDirectoryChangesW`. There is no notification buffer to overflow; a periodic 60-second reconciliation and bounded backlog address missed event detail.

(c) `v42_structured_analyzers.go` now performs limited `debug/pe` static inspection, including entropy, import correlations and overlays. It is **not** a full PE verification or malware unpacker.

## Deviations / limitations
- No change to archive or auto-quarantine score threshold 110 without independent evidence.
- No Windows-native elevation suppression guarantee: Shell `open` avoids requesting `runas`, but Windows may show its own UAC prompts.
- No real-malware CI tests, no unsigned rule-pack update service, no native filesystem driver.
- Do not declare 4.2 field-tested or complete solely because CI passes.
