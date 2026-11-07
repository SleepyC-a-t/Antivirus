# Isolated holdout laboratory runbook (not automated in CI)

**Do not download or execute real malware through this repository or CI.**
Only trained, authorized users with appropriate laboratory controls should
work with externally obtained malicious files. This document intentionally
does not contain malware sources, extraction passwords, or execution steps.

1. Use a physically/virtually isolated disposable Windows VM, with no shared
   folders, clipboard, host-mounted drives, or reachable home/corporate network.
   Start from a verified snapshot; ensure the hypervisor is patched.
2. Obtain samples only from authorized lawful laboratory sources, with a
   documented label, provenance, SHA-256 and handling permissions. Prefer
   non-executable inert examples or published AV test files.
3. Use SentinelGuard **manual, static file review only**. Live monitoring,
   automatic quarantine, and Scan & Run should remain OFF for unknown samples.
   Never double-click or execute a malicious binary or document macro.
4. Run each sample through a static-only harness with a precommitted, frozen
   `labels.json`. Record whether the scanner produced a finding, score,
   reason, skipped/inspection error and the exact sample hash.
5. Separately measure a benign holdout set of known signed Windows files,
   package-managed tools and representative scripts; human-review every
   flagged file before calling it a "false positive".
6. Report per-class TP/FN/FP/TN, skipped rates, confidence intervals, and
   overlap/independence from development fixtures. Do **not** tune detection
   rules against the frozen holdout; a sample used for tuning becomes
   development data and a new unseen holdout is needed.
7. Discard the VM and restore a clean snapshot. Keep hashes and aggregate
   measurements, not raw malicious binaries, in GitHub/ChatGPT reports.

The opt-in `SENTINELGUARD_EXTERNAL_CORPUS` Go test harness only **reads** files
from a local folder and rejects traversal/symlinks. It does not execute samples.
Safety also depends on the host and its primary antivirus, so do not run it
against real malware outside a properly controlled laboratory.

## Confidence intervals

For a binomial count of positives `k` from `n` labeled samples, report the
Wilson score 95% interval, including `n` and the class definitions. For
tiny or author-created datasets this quantifies sampling uncertainty only;
it cannot fix biased labels, training-data overlap or nonrepresentativeness.
