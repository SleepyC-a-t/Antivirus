# Security incident SG-2026-11-07: repeated console windows during full scan

**Status: release/field-test blocker. Do not execute the prior SentinelGuard 4.2 build, and do not resume real-machine testing of this candidate until an independent reviewer (including Claude) has examined the exact patch and Windows evidence.** Code review and CI cannot establish 100% absence of runtime problems.

## User observation and scope

During the first Windows run of the existing v4.2 ZIP, a quick scan and a custom heuristic scan completed, but initiating a full scan caused multiple PowerShell or command prompt windows to appear and disappear. The user aborted immediately. No full-scan JSON was captured, and no process-creation trace was supplied; **therefore the precise observed process identities and parent PIDs are not forensically confirmed**.

Provided JSONs:
- Quick scan: `heuristic:quick`, 3,659 files inspected, 4 skipped paths, 0 findings, empty error.
- Custom scan: `heuristic:custom`, 22 inspected, 3 findings, 0 skipped, empty error.
- Live monitoring and auto-quarantine were disabled. The reports disclose potentially identifying paths; share redacted excerpts only.

## Reproduced causal code path (source-level)

- `scan.go` routes full heuristic scan to `fixedAndRemovableDrives()`, then inspects regular files in parallel using `inspectFileProtected`.
- `v42_structured_analyzers.go` invokes `v42VerifySignature` for PE binaries matching correlated remote-process memory/injection API imports.
- In the previous release `launch_metadata_windows.go` used `exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "...Get-AuthenticodeSignature...")` to obtain certificate subject, **during passive file inspection**. This is the identified source defect and a strong explanation for repeated console windows when scanning an entire Windows installation. The command did not attempt to launch the file being scanned, but spawning command interpreters here is unacceptable. Actual window parent PIDs were not captured.
- Separately, the user-selected Microsoft Defender engine used `exec.CommandContext` to start `MpCmdRun.exe`, without Windows console suppression. The supplied JSON indicates the previous successful scans used the heuristic engine, but no full-scan report exists to establish which engine was selected when the symptom appeared.

## Containment and changes

1. **Removed** the PowerShell subprocess and `os/exec` import from `launch_metadata_windows.go`. Native in-process `WinVerifyTrust` remains; publisher is explicitly reported as unavailable rather than invoking an interpreter. This is a deliberate temporary feature reduction.
2. Added `defender_command_windows.go` / `defender_command_other.go` to ensure the **explicit Defender-only** `MpCmdRun.exe` command has Windows `HideWindow` and `CREATE_NO_WINDOW` flags. This process still runs if the user selects Defender; hiding a console is not a guarantee its child process tree will be terminated on cancellation.
3. Added `TestSafetyPassiveScanCannotSpawnShells` (AST structural lock for process-launch APIs in all non-test Go sources, with explicit user-action exceptions), `TestSafetyPassiveScanOfMixedContentIsReadOnly` (inert content through real scan workers), and Windows `TestSafetyDefenderCommandNeverCreatesConsole` / `TestSafetyNativeSignatureProbeDoesNotUseInterpreter` (no executable started). Tests fail if a future passive scanning component imports `os/exec` or invokes obvious process APIs.
4. Retained all original Stage 6–12 regression suites and independent benign/technique evaluations unchanged. No tuning to hide the issue; unknown Windows behaviors remain unknown.
5. No real-malware samples downloaded or executed by CI, and no new runtime test on the user's computer is requested.

## Required independent reviewer questions for Claude

Review the **exact latest commit** in [draft PR #19](https://github.com/SleepyC-a-t/Antivirus/pull/19), not the old ZIP:
- Is `v42VerifySignature` truly subprocess-free on every path? Are any other analyzer or file traversal paths able to launch code or trigger execution of scanned files?
- Is `WinVerifyTrust` called in a way that is bounded, safe, and not an unexpected UI/network invocation? Are there residual paths or Windows libraries that could still spawn a visible process?
- Is `configureDefenderBackground` applied consistently and do cancellation/restart or process-tree behaviors require stronger safeguards?
- Can the AST source-level lock be bypassed through dynamic calls, DLL APIs, libraries, or future direct Windows APIs? What additional OS-level evidence is required?
- Should full scan (or the entire experimental release) remain disabled until a clean-room Windows process-creation trace is obtained by an independent test operator, rather than the affected user?

**Approval gate:** independent source/code review + CI green at exact SHA + independently run clean-room Windows trace (parent PID, child image, command line, on-screen window behavior, stop behavior), with an explicit sign-off before asking the original user to resume testing.

## Evidence and limitations

The observed symptom is consistent with the source defect, but no recorded process-creation telemetry is available to prove it was the only cause. Removing the spawn path and hiding the explicit Defender console are testable mitigations; a full guarantee of safety or a declaration that Claude approved is **not available**. Keep the incident open until those verification gates are met.
