# SentinelGuard 4.2 — independent review action register (draft)

Source: reviewer checklist submitted 2026-11-07. **Done** = source change + automated evidence exists; **Partly done** = bounded implementation, missing relevant field/independent tests; **Not done** = explicit release limitation. Commit IDs are abbreviated and link to the PR's existing history; do not treat a passing unit test as full Windows validation.

| Reviewer item | Status | Implementation / proof (commit; test) |
|---|---|---|
| P1 Scan & Run Shell/AES/MotW launch path | **Partly done** | `8647e2fa7399`: `ShellExecuteExW` with `open`; final read lock. `fa65154d5087`: Zone.Identifier test. Real SmartScreen prompt is **not field-tested**. |
| P1 check-to-execution race | **Partly done** | `8647e2fa7399`: SHA-256 re-check under file handle with read-only sharing until Shell dispatch. Residual filesystem/loader races exist; no absolute guarantee. |
| P1 SHA/size/signature/publisher/zone/reasons dialog; no misleading clean/inspection errors | **Partly done** | `e2093ec29c4b`: metadata, bounded scan, fail-closed on errors and timeouts. `fa65154d5087`: metadata tests; interactive rendering still untested. |
| P1 never run elevated; no remembered consent | **Partly done** | No `runas` verb or remember-choice; Windows can request UAC elevation from a manifest, and cannot be guaranteed non-elevated without a stronger launcher policy. Documented deviation. |
| P1 optional Explorer context-menu action | **Not done** | Optional and deliberately omitted to avoid changing shell configuration during 4.2. |
| P2 exact EICAR in nested ZIP | **Done within bounds** | `6901a9881015`; `TestV42OfficialEICARMarkerRecursionAndBenignControls`, bomb-budget control. Not full archive coverage. |
| P2 official EICAR ZIP vendor bytes | **Partly done** | `0736c287d714`, `53352f92a84e`; official `eicar_com.zip` hash verified, detected in run 42398762471. `eicarcom2.zip` unavailable, not counted. |
| P2 AMTSO PUA explanation | **Done (documentation)** | `a1e59b8c2cb7`; no special hash added and no unsupported PUA-detection claims. |
| P3 labels and operational/non-operational distinctions | **Partly done** | `e7905978f92b` coverage note distinguishes inert and operational examples, but historical fixture rows have not all been relabeled individually. Legacy test fixtures preserved unchanged. |
| P3 development/frozen holdout + Wilson CI | **Partly done** | `00bef25a336e`; `TestV42BenignFrozenWindowsHoldout` 0/19 (upper 16.82%). No independent ground-truth **malicious** holdout. |
| P3 real benign corpus and reasons; before/after | **Done as finite survey** | `00bef25a336e`, `53352f92a84e`; 7,787 inspected, 5 flagged on both baseline and 4.2 run. Logs disclose each path/reason and per-extension counts. Not representative of all installed software. |
| P3 independent static Atomic Red Team / LOLBAS / AMSI / EICAR | **Partly done** | `b3ac411f3723`, `53352f92a84e`; 4 definitions, 2 flagged; vendor EICAR 1/1 checked. Definitions not malware-labeled. |
| P3 external corpus/lab runbook | **Done harness and runbook** | `0c8f8c3e3aec` `TestV41ExternalCorpusHarnessSafety`; `04582c8cd1bc` runbook. No real malware executed/downloaded in CI. |
| P3 coverage matrix | **Done** | `e7905978f92b` `docs/SentinelGuard-4.2-COVERAGE.md`. |
| P3 README/report generated from CI | **Partly done** | `961402c3511d` time-stamped and run-ID-attributed validation report, CI log artifacts available. Numbers are still manually transcribed; full automatic report generation not implemented. |
| P4 PE inspection | **Partly done** | `f662e5914a86`, `fdc832a30a4d`, `9b4ae8e473f8`; bounded `debug/pe`, import/entropy/overlay with benign lookalikes. No exhaustive version-info parsing. Windows Authenticode applies in launch review, not every full scan. |
| P4 binary LNK, OOXML macro, PDF JS/launch | **Partly done** | `a482023ecf1a`, `9b4ae8e473f8`; positive and benign controls. Parsers are explicitly incomplete. |
| P4 quarantine threshold | **Done (unchanged)** | Still 110, source and README note unchanged by this review. No unsupported sensitivity inference. |
| P5 nonce/HMAC pairing, DPAPI, revoke/re-pair | **Done automated** | `514224d15440`, `e8068b4b95c4`, `44cbe99f996a`; `TestV41DPAPIPersistedBrowserPairingAndRevocation`, browser spoof simulation; real restart pending. |
| P5 literal URL filter metacharacters and near-misses | **Partly done** | `e8068b4b95c4`, `browser_rules.test.cjs`: skips special `*`, `^`, `|` and counts them; string-generation near-miss test exists. Real browser semantics still need field-testing. |
| P5 occupied fixed port | **Partly done** | `514224d15440`; startup failure documented. User-facing behaviour needs field test. |
| P5 Firefox ID and version parity; dead code | **Partly done** | `a1e59b8c2cb7`, both manifests 4.2.0; add CI consistency checks. Version endpoint discrepancy fixed by `75bd9da3f77c`. |
| P5 permanent extension installation | **Not done** | Developer mode / temporary installation only. AMO, Chrome Web Store and enterprise policy are documented routes, not completed. |
| P6 watcher overflow, reconciliation, churn/partial/OFF | **Partly done** | `43ea2fb47d84`, `00201f5a2b82`; `FindFirstChangeNotificationW` has no user-visible event buffer; 60s reconciliation and backlog. `TestV42LiveBurstNeverDropsUninspectedDownloads`, partial download test; real network/cloud folder tests missing. |
| P7 code signing, hashes, provenance | **Partly done** | `4fb4abfb9a2f` packaging CI ZIP+SHA-256, `fa4f81f24b9f` signing guide. EXE unsigned. No artifact attestation configured; SHA-256 not Authenticode. |
| P7 README contradictions | **Partly done** | `a1e59b8c2cb7` removes obsolete restart language; version regression assertions corrected `14b1d997626d`, `0ce49e3c8a72`, API response `75bd9da3f77c`. Automated contradiction check remains limited. |
| P7 privacy-preserving export and launch audit | **Done (bounded)** | `140dba553860`, `7cb5e5428506`, `e371b024dddf`; `TestV42RedactedReportsPreserveEvidenceWithoutLeakingPaths`. Redacted report still includes hashes/timestamps and can reveal sensitive patterns. |
| P7 signed independent rule packs | **Not done by design** | Design-only future topic; no unsigned rule updates in 4.2. |

## Ground-rule verification
1. Current launch path: **ShellExecuteExW with verb open** (not CreateProcess), `launch_windows.go`.
2. Current watcher: **FindFirstChangeNotificationW / FindNextChangeNotification**, **not ReadDirectoryChangesW**; no notification-buffer-overflow callback exists, so a periodic reconciliation is used.
3. Current PE internals: **Yes, limited static** `debug/pe` section/import/overlay checks, not full format coverage.
4. Existing stage tests have not been weakened to force scores. Only stale product-version assertions for 4.1 were updated to 4.2.
5. Every unexecuted field test, failed CI job, skipped public fixture and incomplete detection modality must remain disclosed until directly validated.

## Remaining release gates
- Rerun Windows and Linux CI to green at the exact final commit; downloadable ZIP plus recorded SHA-256 must actually appear as an artifact.
- Verify real Windows launch and UI (including MotW/SmartScreen/UAC), live-browser extension behaviour, restart pairing, churn, and OFF switch.
- Obtain independent labeled malicious and benign samples in a controlled offline lab if making any empirical real-world sensitivity claim. No such claim is made.
