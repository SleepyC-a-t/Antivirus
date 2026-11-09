# SentinelGuard 4.2 — inert technique spectrum: baseline vs candidate

**Date:** 2026-11-09  
**Source baseline:** [`sentinelguard-v42-diagnostic-exports-wide-ui` at `cae8e45f65d27cf17e560015155603c3c9c5815c`](https://github.com/SleepyC-a-t/Antivirus/commit/cae8e45f65d27cf17e560015155603c3c9c5815c)  
**Candidate source (75-case pass):** [`5988d0c3fa8faca8b8e75625e76fc6bbdc54a0de`](https://github.com/SleepyC-a-t/Antivirus/commit/5988d0c3fa8faca8b8e75625e76fc6bbdc54a0de)  
**Test matrix:** [`v48_public_inert_spectrum_test.go`](../SentinelLite_Source/SentinelLite/src/v48_public_inert_spectrum_test.go) (complete inputs and expected labels; no hidden fixtures)  
**Implementation:** [`stage13_behavior_rules.go`](../SentinelLite_Source/SentinelLite/src/stage13_behavior_rules.go), plus bounded integrations in `scan.go` and `scan_advanced.go`.

## Scope / safety

This is a **public-technique-informed synthetic benchmark**, **not** an actual real-world malware dataset and **not** evidence of in-the-wild malware detection sensitivity. The 75 samples are non-deployed, inert static files written into a temporary test directory, then read by the same `inspectFile` path on a Windows CI host. No sampled file is run, installed, deployed on a server, or contacted across the network. The 68-byte standard EICAR vector is tested in memory only in this suite and is **not** counted among the 75. Archive inputs are bounded ZIP entries inspected as static bytes.

The labels `expected=true` mean **a particular illustrative behavior should raise a heuristic warning**, not "confirmed malware"; `expected=false` are hand-selected benign controls, not a representative benign-software population.

## Identical 75-case results

| Family | Expected alerts | Baseline alerted | Candidate alerted | Baseline benign false alerts | Candidate benign false alerts |
|---|---:|---:|---:|---:|---:|
| Disguised files | 3 | 3 | 3 | 0 | 0 |
| Script execution | 3 | 2 | 3 | 0 | 0 |
| Windows LOLBins | 7 | 6 | 7 | 1 | 0 |
| Persistence | 5 | 5 | 5 | 0 | 0 |
| Credential access | 3 | 3 | 3 | 0 | 0 |
| Ransomware-like artifacts | 3 | 3 | 3 | 0 | 0 |
| Browser content | 3 | 3 | 3 | 0 | 0 |
| Server-side web shells | 8 | 0 | 8 | 0 | 0 |
| Office / Windows Script Host | 2 | 2 | 2 | 0 | 0 |
| ZIP archives | 3 | 2 | 3 | 0 | 0 |
| **TOTAL** | **40** | **29** | **40** | **1** | **0** |

- **Baseline:** 29/40 expected alerts; 11 misses; 1/35 benign controls alerted (34/35 clear). [Raw Windows Actions run](https://github.com/SleepyC-a-t/Antivirus/actions/runs/42685567491).
- **Candidate:** 40/40 expected alerts; 0 misses; 0/35 benign controls alerted. [Raw Windows Actions run](https://github.com/SleepyC-a-t/Antivirus/actions/runs/42686537360).
- **Change within this fixed benchmark:** +11 expected detections, -1 false alert. **Do not** call this 100% real malware detection or 0% general false-positive rate. The dataset was used to design the changes; overfitting is a material concern.

## Original misses and engineering response

- Web-shell static indicators: **8 misses** -> extension-bounded, higher-context checks for PHP, JSP and ASP.NET where user-request parameters flow to process/code execution; comment-aware lexical filtering. Still *not* a parser or dataflow engine.
- Script/LOLBins: **2 misses and 1 false alert** -> require stronger co-occurrence, e.g. remote transfer of executable/script and launch of the *same* destination, and corroborated AMSI-related state modification. An isolated transfer remains ordinary software behavior.
- Archive containing server-side script: **1 miss** -> apply the new static web-shell rule within existing ZIP depth, size, ratio, and read-budget limits.

## Public standards / technique mapping

- [EICAR official harmless antivirus test](https://www.eicar.org/download-anti-malware-testfile/) defines the canonical plain and nested ZIP safety test. The 75-case benchmark contains an **in-memory exact EICAR signature check**, not a complete official EICAR download / nested-ZIP test. Previous separate tests exist as `v42_official_eicar_zip_test.go` and `v42_archive_eicar_test.go`.
- [AMTSO Security Features Check](https://www.amtso.org/security-features-check/) describes additional harmless functional tests including PUA and compressed downloads. These are **not equivalent to static fixture detection**. Historical AMTSO PUA miss is **not fixed or retested** by this branch.
- [MITRE ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/) documents web-shell behavior; MITRE ATT&CK also documents T1059, T1218, T1547, T1112 and T1003. Mapping a synthetic file to a technique does not prove it is representative of real malware.

## Release gates and unresolved items

1. Run **complete** Windows `go test ./...` and build, Linux race, browser validation, responsive UI, and existing false-positive survey at the **exact candidate SHA**; the 75-case job by itself is **insufficient**.
2. Independently test *previously unseen* harmless technique variants and a substantially larger collection of benign programs; manually investigate any false alerts. The original benchmark is **not** an independent holdout.
3. Retest the historical EICAR ZIP/nested ZIP cases, scan-process tripwire, native signature code and diagnostic-export privacy protections. Do not launch sample files.
4. Preserve optional protective features OFF by default and keep Microsoft Defender enabled; the binary is unsigned and experimental. Distinguish prior school-computer 14 false positives from the home-computer 347,260-file scan (1 review finding).
5. Do not silently merge or distribute a Windows build until independent code review and appropriate VM verification.

All 75 scenario definitions and their static input strings are preserved verbatim in the committed Go test, making the exact fixed comparison reproducible without distributing potentially active malware.