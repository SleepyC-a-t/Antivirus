# SentinelGuard 4.2 — manual Windows field-test checklist

**Before testing:** keep Defender/Bitdefender active, use only harmless legitimate executables and EICAR as appropriate, and do not override Windows or browser malware warnings. Record Windows version, browser versions, EXE SHA-256, Git commit and any limitations.

- [ ] **Scan & Run and Mark-of-the-Web:** use a known, trustworthy, ordinary downloaded EXE saved with a real NTFS `Zone.Identifier` alternate data stream (`ZoneId=3`), inspect its properties using PowerShell `Get-Content -LiteralPath 'C:\path\file.exe' -Stream Zone.Identifier`, then use the optional Scan & Run flow. Record SHA-256, file size, signature/publisher, Zone.Id and findings shown; verify that applicable Windows download warnings still appear. Do not approve elevation or override Defender to complete this test.
- [ ] **Scan & Run refusal cases:** cancel review, modify/copy a harmless test EXE after approval but before launch, try an unsupported/oversize/locked file. Verify errors do not display a clean verdict and no executable starts without a valid one-time review.
- [ ] **Chrome/Edge and Firefox blocking:** with only harmless controlled URL fixtures (not live phishing), test a known exact blocked URL and near-miss URL using a disposable local page or trusted reserved domain setup. Verify OFF removes blocking and an untrusted localhost responder cannot spoof the app.
- [ ] **Pairing persistence/revocation:** pair extensions, close/restart SentinelGuard and browsers, verify pairing survives, then revoke and ensure the old pairing is rejected until re-pairing. Check the occupied-port error.
- [ ] **Large download and rapid churn:** in a disposable test folder, write large benign data to `.crdownload` / `.part`, then rename to a completed file. Verify no premature inspection; trigger 100+ fast renames/copies, verify no missed settled files after reconciliation, and test long paths and OFF state. Check unsupported cloud/network folders are disclosed as not watched.
- [ ] **Privacy export:** export both full and redacted JSON and inspect manually for your username, paths, private file names, timestamps, identifiers and hashes before sharing.

Log observed versus expected outcomes (PASS / FAIL / NOT TESTED), screenshots with private data removed, startup errors, and browser extension versions. **This checklist has not been run interactively by CI.**


## Additional 4.2 security-retest steps (independent Sandbox operator only)
- [ ] **Open location:** with a known inert file in the read-only mapped fixture folder, click Open location and verify that Explorer opens the containing directory and selects the expected file, with no command prompt or PowerShell child.
- [ ] **Open Windows Security:** click once and verify correct Windows Security page, no unexpected command interpreter process, no elevation prompt from SentinelGuard, and no external URL navigation. Record success or failure if Windows Sandbox does not provide that system UI.
- [ ] **Toolhelp child tripwire:** inspect the OS-observed count, child image names and PID list while a benign heuristic scan runs and at completion. Expected zero. Check `childProcessSampleCount` increases; unknown/failed monitoring must not appear as zero/clean. Compare to Process Monitor because 250-ms snapshots can miss short-lived children.
- [ ] **Signature wording:** inspect a legitimate Windows catalog-signed file such as notepad.exe. 'Not verified' must be described as missing embedded/catalog verification, not as evidence of malware.
- [ ] **Sandbox and filtering:** open `docs/SentinelGuard-Safety-Review.wsb` (create the mapped source folder first), follow `docs/SentinelGuard-Procmon-Filters.txt` to save the native Procmon filter and preserve raw unfiltered PML.
- [ ] **Cancelled scan:** start then cancel a full heuristic scan of benign fixtures, checking whether unexpected child processes appear and whether CPU/memory/tripwire and Stop state settle.
**Reminder:** No test on the affected personal machine while the SECURITY HOLD remains active. The Windows Sandbox configuration and Procmon guide are for an independent tester; success on them still does not establish 100% safety.
