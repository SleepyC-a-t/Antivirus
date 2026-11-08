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


## Historical source reconstruction and filename-injection concern (priority 8)

The **exact revoked source** at
`c1770d9dba6ba57604e89526e29f545bf293589d:SentinelLite_Source/SentinelLite/src/launch_metadata_windows.go`
constructed a PowerShell command by concatenating the file path into single-quoted
PowerShell script text, *then launching powershell.exe*:

```go
escaped := strings.ReplaceAll(path, "'", "''")
script := "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped +
    "'; if($s.SignerCertificate){$s.SignerCertificate.Subject}"
cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
raw, err := cmd.Output()
```

**ASCII apostrophe:** U+0027 was doubled to U+0027 U+0027, the normal
PowerShell single-quoted-string escape. That mitigates literal ASCII apostrophes
in this specific embedding.

**Curly / smart quote:** U+2018, U+2019, U+201A and U+201B were **not**
normalized, doubled, or escaped. PowerShell recognizes smart quote characters
as quote tokens in some contexts. Consequently, untrusted file paths containing
these characters are a **possible filename-driven command-injection risk** in
the revoked version. That risk has not been confirmed by controlled exploitation
and no payload was executed. However, the risk is sufficient to keep the old
build revoked. The remediation eliminates PowerShell construction altogether,
rather than attempting to patch escaping.

The original `Get-AuthenticodeSignature` command retrieved certificate
metadata, not the scanned program's entry point. The injection concern is a
separate potential execution path *through the interpreter itself*; it does
not mean the scanned binary was intentionally executed.

## Native trust checker after remediation (priority 4)

The patched `v42VerifySignature` now:
- Passes Windows `INVALID_HANDLE_VALUE` for `hWnd` and sets WTD_UI_NONE=2,
  WTD_REVOKE_NONE=0, WTD_CACHE_ONLY_URL_RETRIEVAL=0x1000 and
  WTD_REVOCATION_CHECK_NONE=0x10.
- Uses `runtime.KeepAlive` to retain Windows API input buffers and structures.
- Separately labels common HRESULT failures and does **not** treat no embedded
  signature as trusted; independent catalog-signed file checking
  (`CryptCATAdmin*`) is not implemented and is explicitly disclosed.
- Bounds the **caller's wait** to 2.5 seconds and permits at most 2 concurrent
  native trust calls. The native WinVerifyTrust function itself is synchronous
  and **cannot be forcibly terminated by this timeout**. A hung invocation may
  occupy one of the two slots indefinitely, and later verifications are reported
  unverified rather than allowed to accumulate threads.
- Leaves publisher text **unavailable** until native certificate extraction
  receives an independent security review. It starts no interpreter.

In particular, the current 48-point remote-injection-import PE rule remains
correlative, **not proof of malware**. The new read-only Windows CI
`TestSecurityThirdPartyPEImport48PointRuleSurvey` reports sampled
third-party parsed PE counts and rule matches, while explicitly recording
unavailable game-launcher roots rather than inventing their results.

## Process counter and remaining experimental Defender boundary

`status.childProcessesStarted` counts process starts initiated directly by
SentinelGuard's selected external Defender helper. It resets per scan; heuristic
scan expects 0. This is **application bookkeeping only, not an OS-level
process monitor**. Scanned files never contribute to the counter because they
are not intended to run.

In explicitly selected Defender mode, a Windows Job Object is configured with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Assignment occurs just after
`cmd.Start`, leaving a narrow assignment race. Failure to configure or assign
the Job Object fails closed and kills the root process. Closing the Job Object
after completion attempts to terminate remaining descendants. The separately
managed Windows Defender service may continue independently. Defender remains
optional and OFF by default.

## Windows Sandbox / Process Monitor independent lab runbook

Only an **independent test operator**, not the affected user, should perform
this while the incident remains on hold:

1. Use a disposable Windows Sandbox or isolated Windows VM with networking and
   clipboard/drive sharing disabled; avoid administrator access except where
   Process Monitor/ETW capture explicitly requires it. Use no live malware and
   no untrusted downloads.
2. Copy only reviewed source/build artifacts and harmless benign test fixtures
   into the isolated environment. Record commit SHA, executable SHA-256, Windows
   build, antivirus status, and tool versions.
3. Obtain the official Microsoft Sysinternals **Process Monitor** from a trusted
   organizational source and verify its Authenticode signature. Set filters for
   `Process Create` and `Process Exit`; include SentinelGuard and
   PowerShell/CMD/console hosts, preserving both included and excluded counts.
4. Start capture **before** launching the app. Execute the isolated benign-tree
   heuristic full-path scan and stop it normally, then repeat a cancellation
   mid-scan. Do **not** approve Scan & Run or execute any specimen.
5. Export raw `.PML` and sanitized `.CSV` with timestamp, process image,
   PID, parent PID, command line, exit status, scanned file count and trust
   invocation count. Compare an old build only inside this isolated lab; never
   on a personal host.
6. Require **old `powershell.exe` count greater than zero in a fixture that
   actually exercises the signed triple-import path**, and patched count zero
   over the same fixture. If the ordinary benign survey does not exercise that
   path, record it as inconclusive and use a separately labeled controlled
   signed fixture; do not reclassify a direct-verifier control as a full-scan hit.
7. Review event logs, close and discard the VM, then submit minimized evidence
   and a written sign-off. Actual user-machine tests remain prohibited until
   the independent assessor confirms the safety gate.

### OS trace method under CI
`.github/workflows/sentinelguard-v43-process-forensics.yml` checks out
both commits on the same Windows runner, runs a common read-only expected-benign
survey and a **separately labeled direct signed-file verification control**,
records `v42VerifySignature` invocation counts, and requests
`Microsoft-Windows-Kernel-Process` ETW output through `logman`,
`Get-WinEvent`, and `tracerpt`. Raw ETLs are uploaded. Do **not** claim
that ETW captured command lines or a parent-child tree unless the actual
resulting event payload contains those fields. A CI headless startup test is
not equivalent to interactive console-window observation.


## 2026-11-08 — Claude review follow-up and verified forensic corrections

**Fixed in CI, pending independent Windows field verification.** Claude's
independent review of the previous 4.2 candidate accepted the specific
PowerShell regression fix and independently verified 8 old versus 0 patched
`powershell.exe` children in the same scanner survey. A controlled retest
was not blocked by that issue, but the SECURITY HOLD banner remains until
the user-controlled and independent Windows Sandbox field-test gates are met.

**Exactly what ran:** the ETW comparison executed a **Go test binary**
containing the real SentinelGuard scanner and the same real benign-file
inspection functions, **not the desktop GUI executable**. The GitHub workflow
built both historical and patched desktop EXEs for byte-level inspection and
recorded their SHA-256 hashes; it did not execute those desktop EXEs during
the ETW survey. A separate Windows CI smoke test launched the patched GUI
backend headlessly.

The patched build embedded inside the old 4.2 review ZIP has
SHA-256 `a4bfbfa60d3349d8420b837cc07fd7244f64c9f51454a756cb1de520c5e42842`.
The patched desktop EXE built in the exact matching ETW comparison has
**the same SHA-256**, not a different one. A previous handoff report
incorrectly claimed a hash mismatch; it is corrected here.
The revoked historical desktop EXE SHA-256 in that ETW run was
`74ee732e8108c3c83bdb869916291f0ca2981e8164ec3e96e2c3bf8c0c047bf8`.
These are specific historical artifact hashes, not hashes of future builds.

**Performance (same selected CI survey):** the historical Go scanner test
took **111.43 seconds** and the patched scanner test **12.99 seconds**.
Each inspected 7,787 expected-benign files and invoked the signature
verification path 8 times during the survey. These timings are CI-specific,
not general full-drive performance benchmarks or a guarantee of future speed.

**Observed process tripwire:** The new `status.childProcessesObserved`
and `childProcessEntries` are sampled with the native Windows Toolhelp32
API at scan start, 250-ms intervals and scan completion; results contain
direct child PIDs, executable base names and first-seen timestamps. Any
observed child during heuristic mode produces an explicit warning.
Because snapshots are not continuous ETW, a child that starts and exits
between samples may be missed. `childProcessMonitoringError` reports
sampling failures. It does NOT replace forensic ETW or Sysmon.

**Signature interpretation:** `Not verified` is neutral/unverified, not
proof of malware. The offline native checker handles embedded signatures
only and does not resolve all catalog-signed files; Windows notepad.exe
can report not verified even when legitimate. Trust verification is a
supplementary static signal, never a guarantee that a file is safe.

**Defender Job Object:** Explicit experimental Defender scanning remains
OFF by default. The helper now starts in CREATE_SUSPENDED state, is
assigned to a kill-on-close Windows Job Object, and is only resumed after
successful assignment. A Win32 Toolhelp thread snapshot is used to locate
its suspended thread. The external Defender service can still continue
independently; no antivirus cancellation guarantee applies to that service.

**Controlled tester resources:** `docs/SentinelGuard-Safety-Review.wsb`
provides networking-disabled Windows Sandbox configuration with a
read-only host folder mapping (create `C:\SentinelGuardReview` first).
`docs/SentinelGuard-Procmon-Filters.txt` provides explicit manual Process
Monitor filter rules, process-tree checks and evidence-preservation steps.
It is not a native .PMC file and must not be described as one.

**Independent field verification and release blockers:** visual GUI
button behavior (Open location and Windows Security), a complete and
cancelled full-drive run in an independently controlled sandbox, no
signing certificate, no independently labeled real-malware sensitivity,
and a final reviewer sign-off remain outstanding.

