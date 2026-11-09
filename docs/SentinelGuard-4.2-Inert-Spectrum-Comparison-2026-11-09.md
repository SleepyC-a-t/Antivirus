# SentinelGuard 4.2 — Inert threat-spectrum before/after comparison

**Date:** 2026-11-09. **Scope:** 75 purpose-built, fully static fixtures and 1 in-memory EICAR self-check. **Risk:** no live malware, no execution, no downloads, no system changes, no browser/PowerShell/cmd launches. `example.invalid` and illustrative file names only.

## Data provenance and limits

The fixture designs are original inert emulations informed by public MITRE ATT&CK descriptions and approved antivirus test guidance. They are **not** malware samples copied from public repositories, active Atomic Red Team exercises, or real-world labeled malware. This matters: a regex scanner detecting an example that resembles a technique is not proof that it detects a malicious binary implementing that technique. The true-negative set likewise consists of human-labeled harmless controls, not a representative population of production software.

- EICAR harmless AV test vector: https://www.eicar.org/download-anti-malware-testfile/
- AMTSO Security Features Check, approved non-malicious verification: https://www.amtso.org/security-features-check/
- MITRE ATT&CK T1059 command and scripting interpreters: https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1505.003 web shells: https://attack.mitre.org/techniques/T1505/003/
- MITRE ATT&CK T1112 modify registry: https://attack.mitre.org/techniques/T1112/
- Public research metadata only, **not** used as raw file corpus: EMBER2024 (https://arxiv.org/abs/2506.05074). Its feature vectors/labels cannot be scanned by the current read-only file-bytes pipeline without a separately validated feature adapter.

Reproducible corpus and test code: `SentinelLite_Source/SentinelLite/src/v48_public_inert_spectrum_test.go`. Archive samples are generated directly in memory and scanned as ZIP files in ephemeral Go test directories; no ZIP entries are extracted or executed. The 68-byte EICAR standard is reconstructed and checked **in memory**, not written to disk (which could trigger the host's own antivirus and alter the test outcome).

**Labels:** `expected=true` means *we expect a review alert* based on multiple suspicious indicators, not `malware=true`. `expected=false` means an intentionally benign control. No file is launched.

## Exact CI before/after runs

- **Before (unchanged original detector):** commit `7cdd6ba567516bdbd2757e61d62785f59c2cfb9b`, [Windows CI job](https://github.com/SleepyC-a-t/Antivirus/actions/runs/42685567491): **SUCCESS**
- **After (updated detector, same 75 fixtures):** commit `5988d0c3fa8faca8b8e75625e76fc6bbdc54a0de`, [Windows CI job](https://github.com/SleepyC-a-t/Antivirus/actions/runs/42686537360): **SUCCESS**
- Subsequent test-only commit adds **a hard regression assertion** to fail future CI if the 75 fixture labels are no longer met.

### Overall confusion matrix on synthetic labels

| Metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Positive fixtures with expected review alert | 29 / 40 | **40 / 40** | +11 |
| Expected positive fixtures missed | 11 | **0** | -11 |
| Benign fixtures falsely alerted | 1 / 35 | **0 / 35** | -1 |
| Benign fixtures correctly left alone | 34 / 35 | **35 / 35** | +1 |
| Expected-alert agreement | 72.5% | **100%** | +27.5 percentage points |
| Benign agreement | 97.14% | **100%** | +2.86 percentage points |

### By behavior family

| Family | Positive alerts before/total | After/total | Benign wrongly flagged before | After |
| --- | ---: | ---: | ---: | ---: |
| Disguised names/formats | 3 / 3 | 3 / 3 | 0 / 3 | 0 / 3 |
| PowerShell/scripts | 2 / 3 | **3 / 3** | 0 / 4 | 0 / 4 |
| LOLBins / download chains | 6 / 7 | **7 / 7** | 1 / 4 | **0 / 4** |
| Persistence | 5 / 5 | 5 / 5 | 0 / 4 | 0 / 4 |
| Credential access/exfiltration | 3 / 3 | 3 / 3 | 0 / 3 | 0 / 3 |
| Ransomware-like indicators | 3 / 3 | 3 / 3 | 0 / 2 | 0 / 2 |
| Browser/HTML/SVG | 3 / 3 | 3 / 3 | 0 / 2 | 0 / 2 |
| PHP/ASP.NET/JSP web shells | **0 / 8** | **8 / 8** | 0 / 8 | 0 / 8 |
| Office/Windows Script Host | 2 / 2 | 2 / 2 | 0 / 2 | 0 / 2 |
| ZIP static artifacts | 2 / 3 | **3 / 3** | 0 / 3 | 0 / 3 |

The 68-byte exact EICAR signature passed an in-memory recognition check both before and after. It is not counted among the 75 cases.

## Original 12 discrepancies and changes

- **PS02 — false negative:** AMSI-related type name and disabling-state assignment were split across a reflective `GetType(...)` expression and assignment. New rule requires both on actual PowerShell code, not isolated terminology.
- **LOL09 — false negative:** BITS retrieval of an executable/script followed by `Start-Process` of the same file. New rule requires both remote download and an output-target-matched launch; a transfer alone remains benign.
- **SHELL01–SHELL08 — eight false negatives:** PHP `.php/.phtml`, ASP.NET `.aspx/.ashx`, and JSP `.jsp` server-side scripts were not inspected in the prior file-extension dispatch. New bounded static inspection requires a web-server script opener, HTTP request parameter and direct or locally assigned use as a process/code-execution argument. Generic `shell_exec`, `Process.Start`, `Request` or `getParameter` strings alone are not scored.
- **ARC05 — false negative:** PHP request-driven command execution hidden inside a ZIP member. The existing safe, bounded archive inspection now calls the same rule on fully read eligible entries, without extraction or execution.
- **LOL05 — false alert:** A standalone `certutil -urlcache` transfer had an alert score of 46 despite no execution or related behaviors. It now contributes only a weak score of 18. **Transfer-and-launch** of the same downloaded `.exe/.cmd/.ps1/.bat` receives a separate high-context review alert. This consciously trades away standalone-transfer detection in favor of lower benign false positives.

## Scanner change inventory

- `stage13_behavior_rules.go`: added isolated high-context rule parser.
- `scan.go`: opted in only recognized server-side extensions to bounded content sampling and changed certutil-only score to a weak signal.
- `scan_advanced.go`: added the new rule to bounded fully-read ZIP members, without changing decompression or execution limitations.
- `v48_public_inert_spectrum_test.go`: immutable 75-case benchmark, now a regression gate.
- `.github/workflows/sentinelguard-inert-spectrum.yml`: Windows automated benchmark and per-case result artifact.

## Remaining unknowns and risks

- **100% of 40 expected synthetic review alerts does not imply 100% malware detection.** Known signatures, compiled binary behavior, novel malware, kernel activity, memory-only attacks, PDF object-stream content, evasive or encrypted payloads, and real production software are not measured by these cases.
- Rules based on server-side request-to-execution patterns can be present in legitimate administration pages and debugging tools; findings remain advisory and should never auto-quarantine solely on these signals.
- Additional benign real-world corpora, full Go unit/regression tests, OS child-process checks, and Windows VM review must pass before treating this change as a release candidate.
- The regression test is partly a **tuned development suite**. To measure true generalization, evaluate a held-out independent labeled set; do not repeatedly tune to a holdout while calling it independent.
- No live malware binaries or active red-team commands are distributed by this branch. No claim is made about real-world AV benchmark ranking.

**Important:** Do not merge this branch to main until all current Windows security regressions and benign comparisons pass at the final exact source SHA, with the existing staged pull requests reviewed in the correct order.
