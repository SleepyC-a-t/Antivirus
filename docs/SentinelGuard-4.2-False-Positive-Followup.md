# SentinelGuard 4.2 — Main-PC field report and false-positive triage

## Confirmed user observations (2026-11-09)

The user reported that a controlled full scan on their normal Windows installation completed, without an apparent recurrence of the historical PowerShell child-process incident. They independently identified **14 findings as false positives**.

**Critical evidence limitation:** The uploaded `SentinelGuard_v4.2_Live_Report.json` is a **live protection status** export, not the **manual full scan** export. It includes `enabled:false`, `autoQuarantine:false`, `inspected:0`, `flagged:0`, an empty live-event log, and `launchReviewEnabled:false`. It contains **none of the 14 manual scan finding paths, scores, severities or detection reasons**. As a result, the precise 14 false positives have **not been reproduced, located or individually corrected**. No statement should imply otherwise.

## Narrow evidence-based improvement in this patch

- The former v4.2 PDF scanner could count PDF action words anywhere in the sampled bytes, including PDF titles, explanatory text, escaped parentheses and comments. It now looks for syntactically recognized **PDF dictionaries**, requiring document-open and JavaScript action dictionary evidence or a same-dictionary `/S /Launch` + executable filename pairing.
- Added regression cases for benign PDF documentation, comment examples, syntactic mismatches and genuine PDF action structures. No PDF action bytecode or target is executed.
- Still a bounded lexical parser; it does not decompress PDF object streams, confirm cross-object action references or establish exploitability. A malicious PDF that evades the sampled dictionary grammar may not be detected.
- The full scan JSON now has `reportKind:"manualScanFindings"` plus `findingReasonsSummary` containing aggregate *coarse* rule-family counts, maximum scores and no filenames. The live status JSON is explicitly `reportKind:"liveProtectionStatus"`.
- GUI buttons are labeled **Export scan findings JSON** and **Export live-protection status (not scan findings)**. A dedicated **redact identifying paths** checkbox is selected by default for the manual report.
- The obsolete broad `SECURITY HOLD — REVIEW-ONLY` banner was replaced with an unobtrusive, truthful notice that this is a supplemental heuristic tool with unverified real-malware sensitivity. **Unexpected-child and process-monitoring-failure warnings remain active**. Microsoft's Defender should remain enabled.
- Do not disable or quarantine findings just because the user called them false positives; no rule allowlist or unsigned-file trust exception was added.

## Getting the actual 14 findings

In the Windows application, open the **Findings** tab after a completed heuristic scan and select **Export scan findings JSON**. This creates `SentinelGuard_v4.2_Scan_Findings.json` from `/api/report`. Retain **Redact identifying paths** checked before sharing. A full scan report includes `findings` entries with `score`, `severity`, and `reasons`; it also includes a path-free rule-family summary. It is not the `...Live_Report.json` file. Review all report fields before uploading. In the current user-supplied export those findings do not exist.

The old manual scan data may be lost if a new scan already reset the in-memory findings list. If so, a new controlled scan can regenerate them; no need to upload suspicious executable samples for basic rule triage.

## Release status

- Historical PowerShell launch defect: fixed in CI, validated with ETW and controlled Windows VM/host testing.
- WebView2 false anomaly: verified signed and machine-installed runtime can be attributed; independent Windows VM/host observations were reported.
- Scanner detector: **14 reported field false positives remain unattributed** until we have their reasons and sample metadata. The PDF structural change addresses a separate demonstrable false-positive pattern and is not proven to account for those 14 cases.
- Protection engine: no independently labeled, large-scale real-malware sensitivity measurement; still unsigned. Keep ordinary antivirus enabled.
- CI gates: Windows Go tests, native child-process regressions, expected-benign comparison, browser UI checks, Linux race checks. Keep PR draft until checks pass and findings review is complete.

This document deliberately distinguishes field observations, code-level improvements, and work that remains to be verified.
