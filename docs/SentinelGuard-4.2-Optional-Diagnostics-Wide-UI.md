# SentinelGuard 4.2 — Opt-in scan diagnostics and wide-window layout

## Motivating field scan (2026-11-09)

The supplied **redacted manual full-scan** report records:
- **347,260** files inspected
- **1 Review-level finding** (score **51**, approx. 5.45 MB): an executable in a temporary folder with a PE remote-memory API import triad. Neither indicator proves malware. The report did not include publisher/trust results or matched import identifiers.
- **338** skipped paths (mostly access denied and intentionally unfollowed reparse points; a small group of invalid ZIPs).
- **1 expected, signed WebView2 interface child**, **0 unexpected** children. Toolhelp32 polling cannot rule out all short-lived processes.

All file names and Windows paths are omitted from this document. The field report is advisory, not independently labeled as a confirmed malware or false positive.

## Opt-in export

In **Findings → Export scan findings JSON**, the options are now:
- **Redact identifying paths** — ON by default.
- **Include optional diagnostic data** — OFF by default, requires explicit selection for each export.

The manual scan endpoint `/api/report` accepts `diagnostics=1` to add:
- `diagnosticsIncluded: true`, `diagnosticSchemaVersion: 1`
- `diagnosticData` (up to **64** findings, limited and sorted by existing finding priority)
- `diagnosticsOmitted` and `diagnosticPrivacyNotice`

Each diagnostic references the existing finding ID, and contains status (`collected/changed/missing/nonregular/unreadable`), file extension, recognizable header type (no header bytes), size at scan and export, and safe coarse indicators such as **temporary-location rule**. An unchanged file may include its **SHA-256 computed during the scan**, which is masked when report redaction is selected.

For ordinary PE files up to 64 MiB, diagnostics may include processor machine, section count, number of imported symbols, **only seven relevant remote-memory API names**, allocation/write/thread triad flags, highest sampled executable entropy, whether executable section entropy exceeded 7.55, packer-like section naming, substantial overlay, and the result of the existing **native offline Authenticode verifier**. A signature is useful context, not proof that a file is safe or Microsoft-published.

Every optional diagnostic read is **strictly opt-in** and occurs locally at export time. File contents, disassembly, scripts, strings, passwords, macros, browser history, private keys and arbitrary PE import names are not exported. The exporter does not execute or launch programs, and intentionally stops when file size/mtime changed from the original scan. The file can still change between checking metadata and reading it (TOCTOU); this report is **diagnostic context, not forensic attestation**. An attacker can manipulate timestamp metadata. For unreachable files, the report uses error categories without echoing the native path.

### Privacy

- The old redacted report exposed some Windows filesystem error text after a path containing spaces; **skipped-path reasons are normalized** to safe categories in redacted exports. File paths, names and SHA-256 are separately masked with per-export randomized identifiers.
- Even with redaction selected, **timestamps, score, size, PE import indicators, entropy and signed/unsigned status** can identify a particular program. Review before sharing.
- There is **no telemetry**, internet upload, file execution, or automatic quarantine tied to diagnostic export.
- The standard export path remains unchanged when the optional checkbox is OFF.

## Responsive overhaul

The dashboard now uses the **actual app/WebView viewport width** rather than a fixed 1,560-pixel wrapper cap. At large widths it grows edge to edge with restrained padding, places Findings and CPU/RAM/child-process information in **two functional columns**, increases resource tile density where space allows and removes the 590-pixel nested vertical scroll for the findings table. On narrower windows, the scanning side panel collapses above the dashboard, and findings become compact review cards with intact actions. Light/Dark/System preference and all backend element IDs are preserved.

Browser checks run at 360, 768, 1024, 1440, 1920, 2560 and **3440** pixels and verify no document horizontal overflow, wide-window utilization, theme persistence, opt-in diagnostic checkbox default OFF, and privacy redaction default ON.

## Test and release criteria

- Unit tests for normal vs opt-in exports, hash and skipped-error redaction, user-supplied inert content never entering reports, changed-file detection and cap.
- Existing Stage 6–12 and Windows process safety regressions, Windows EXE build, benign comparison, browser extensions, responsive layout checks and OS process trace.
- All source changes are in a separate draft PR based on prior PR #23; do not merge out of order.

This is a supplementary experimental heuristic scanner; it is not a substitute for Microsoft Defender or independently benchmarked malware detection.
