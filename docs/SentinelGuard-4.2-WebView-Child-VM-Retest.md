# SentinelGuard 4.2 — WebView2 child-process classification, VM retest

**SECURITY HOLD — review-only, fixed in CI for the original PowerShell defect; this new change remains pending CI and independent field verification.**

## Reported field observation

A user tested the earlier UI candidate in a Windows 11 VirtualBox VM. A heuristic full scan of about **141,000 files** completed without a reported crash or false-positive finding. Toolhelp32 sampled **2,887** times and observed one direct child:

- `pid=2232`, `parentPid=7924`
- `image=msedgewebview2.exe`
- `firstSeen=2026-11-09T13:20:23.0350453+01:00`

The earlier monitor correctly recorded that child but indiscriminately raised a scanner-process warning. Microsoft WebView2 normally runs `msedgewebview2.exe` as part of its native host interface, so the event is *consistent with* an expected GUI child. **The original report did not include a full executable path or cryptographic signer identity, so this particular observed PID is not independently verified as genuine Microsoft WebView2.** `firstSeen` is the sampling time, not necessarily the creation time.

## Corrected fail-closed policy

The Toolhelp32 observation path still counts **every direct child** (including GUI helpers). On Windows, for each newly detected process identity it now queries the actual image path and native process creation time with read-only Windows APIs. The application classifies a child as `expected-webview2` only if **all** of these hold:

1. OS snapshot reports that its parent PID is the running SentinelGuard process.
2. Its image name is exactly `msedgewebview2.exe` (case-insensitive).
3. The OS reports its full image path and the path matches the exact `Microsoft/EdgeWebView/Application/<numeric version>/msedgewebview2.exe` layout under the Windows **machine registry's** Program Files roots (not environment variables, user-writable application folders, or a name-only exception).
4. Its **embedded** Authenticode signature verifies with the existing in-process, offline, noninteractive WinVerifyTrust check. If the check is busy, times out, cannot verify a catalog signature, or reports untrusted, classification fails closed.

A matching UI child remains in `childProcessEntries` and increments both `childProcessesObserved` and `childProcessesExpected`; it **does not, by itself, generate the heuristic-execution warning**. Every other child increments `childProcessesUnexpected` and causes that warning, including a spoofed WebView2 filename or a WebView2 path/signature the app cannot verify. Failures of Toolhelp32 process sampling also remain warnings.

**Limits:** This verifies a trusted signature and a protected runtime installation location but does **not** independently parse or establish the Microsoft certificate publisher. It is a conservative attribution signal, not a security guarantee. The current embedded signature checker does not resolve catalog-signed files; a genuine WebView2 binary may remain `unverified-webview2` and still generate a warning. That is correct fail-closed behavior. Process creation times help distinguish PID reuse; when Windows denies access, do not infer identity. Sampling every ~250 ms may miss short-lived children. This does not replace Process Monitor/ETW.

## VirtualBox Windows 11 retest checklist

1. **VM only:** Take a snapshot of a clean disposable Windows 11 VM. Disconnect network and disable shared writable host folders; keep Microsoft Defender enabled. Verify the downloaded ZIP hash and reviewed commit before extraction.
2. Start SentinelGuard with the **SECURITY HOLD** still displayed. Check Light, Dark and System appearance modes and resize the GUI. Check that Windows Security/Show in Explorer buttons do not cause unexpected command interpreters.
3. Start an expected-benign heuristic full scan. Open the app's resource section and confirm that **all observed children remain counted** and that separate expected/unexpected totals appear.
4. For the genuine WebView2 runtime, the desired outcome is `classification="expected-webview2"`, a machine-managed `executablePath` and `signatureStatus="Trusted embedded signature (offline; revocation not checked)"`. An unexpected/unverified WebView2 child is **not automatically a scanner defect**; preserve its full evidence for investigation rather than suppressing the warning.
5. Require `childProcessesUnexpected=0`, `childProcessMonitoringError` empty, substantial `childProcessSampleCount`, no crash, and no new suspicious file findings to consider the retest successful **for this VM's benign corpus only**. Do not interpret a clean screenshot as proof of process creation absence.
6. Ideally record the scan with native **Process Monitor or ETW** and preserve child PID, parent PID, full path, and command lines; compare with Toolhelp32's sampled findings. Confirm no unexpected `powershell.exe` or `cmd.exe` spawned. Retain unfiltered evidence where possible.
7. Export SentinelGuard's report with path redaction enabled before sharing. In an unredacted report, the new `childProcessEntries[].executablePath` may contain installation/user paths; `creationTimeTicks` and timestamps can be identifying. A redacted copy may omit path evidence needed to validate the signer, so retain raw local evidence privately for independent inspection.
8. After the scan, close the application and discard/revert the VM snapshot.

**Release gates:** A clean VM test is a major positive result but is not a proof of universal safety. Do not automatically lift the personal-machine security hold. Obtain independent review of the changed process-identity policy and VM process trace, then consider a **staged** Windows host test (restorable backup, Defender enabled, no active protection, quick scan first). Real-world malware sensitivity, code signing, and complete full-drive field testing remain distinct gaps.
