# SentinelGuard 4.2 — optional offline static-malware lab runbook

**Scope:** user-controlled, authorized, isolated testing of existing samples. **Never execute real malware** in this procedure; CI must not fetch or execute any. Do not disable endpoint protection on your everyday host to bypass warnings.

## Environment
- Use an explicitly authorized laboratory machine or disposable VM with no shared folders, clipboard sharing, host mounts, USB passthrough, network adapter, or access to private data. Take an initial immutable snapshot; label sample origins and permitted handling.
- Obtain test material only through authorized sources and according to license, jurisdiction and laboratory policy. Prefer harmless EICAR and inert synthetic fixtures initially.
- Use a preapproved file-transfer procedure; do not carry live samples through personal browsers, sync folders, email, or production endpoints.
- Capture OS build, SentinelGuard commit/release hash, Defender status, SHA-256 of each static sample, declared independent ground truth and who assigned it; avoid recording private usernames or paths.

## Static-only protocol
1. Take a fresh isolated snapshot and confirm all external connections and host integration are disabled.
2. Inspect every sample **as data only** with SentinelGuard's manual scanning or the opt-in external corpus harness. Do **not** double-click samples, open scripts in execution hosts, turn on Scan & Run, open suspicious documents in Office, or unpack with tools that auto-execute.
3. For each sample record: identifier, type, hash, known ground-truth classification/quality/source, scanner decision and full reasons, errors/skipped and scan duration. Record unsupported or too-large files as **uninspected**, not clean.
4. Put training/development samples in a separate group. Freeze an independent labeled holdout **before tuning**. Never tune on the holdout.
5. Compute TP, FN, FP, TN and Wilson 95% confidence bounds only for genuinely independent **labeled** datasets; report EICAR and synthetic regression locks separately.
6. Revert the VM to the clean snapshot after testing. Preserve sanitized summaries, not sample binaries, in publicly shared reports.

## Interpretation and safety
A static signature-free heuristic scanner cannot guarantee absence of malware; encrypted/packed files, document exploitation and memory-resident techniques may evade it. Harmless test strings and attack-definition documents do not constitute executable malware. Never publish real malicious samples in GitHub Actions artifacts or attach them to routine feedback reports.

Use `SENTINELGUARD_EXTERNAL_CORPUS` only in an offline VM, with the expected format and safety checks documented by the repository's `v41_external_holdout_test.go`. No real-malware evaluation has been performed by this draft.
