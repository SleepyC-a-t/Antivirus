# Independent holdout evaluation — SentinelGuard 4.1

The existing Stage 6 and Claude synthetic test fixtures were known to the
scanner developer. They are useful for *regression testing* but are **not**
independent real-world detection benchmarks.

This opt-in evaluation harness tests **outside, independently labeled** sample
files without executing them. No heuristics are changed during evaluation.
It never launches files or quarantines them.

## Prepare data
Create a folder containing an independently sourced, legally obtained,
safely stored set of known-benign and separately labeled suspicious files.
Do not collect or handle live malware outside a professionally isolated lab.

Include `manifest.json` at the corpus root:

```json
{
  "version": 1,
  "source": "Third-party lab or source name and revision/date",
  "labelProvenance": "How and by whom each sample was classified",
  "samples": [
    {
      "path": "harmless_sample.txt",
      "label": "benign",
      "sha256": "64-character lowercase SHA-256 hex digest"
    }
  ]
}
```

- Only relative file paths beneath the manifest directory are allowed.
- The evaluator validates each SHA-256 and avoids symlinks and reparse points.
- It uses the *same static scanner* as the application, without running samples.
- Up to 5,000 entries are supported; unreadable files are tracked separately,
  not incorrectly counted as correct detections.
- Class labels are externally supplied. An inert example can be labeled
  suspicious without being executable malware; interpret results accordingly.

## Run the optional holdout test

From `SentinelLite_Source/SentinelLite/src`, with Go 1.23+:

```powershell
$env:SG_HOLDOUT_MANIFEST = "C:\SafeCorpus\manifest.json"
$env:SG_HOLDOUT_REPORT = "C:\SafeCorpus\holdout_results.json"
go test -v -run '^TestIndependentHoldoutIfProvided$' .
```

The JSON report contains paths, detection scores, matched heuristic reasons
and test labels. Review and redact personal data before sharing. If an external
corpus is not supplied, CI marks the holdout test SKIPPED rather than making up
an independent detection percentage.

**The 4.1 release currently has no independently measured real-malware
detection rate.** Keep Defender or another established antivirus enabled.
