#!/usr/bin/env python3
"""Convert immutable Go CI log into a reproducible, transparent summary.
Do not turn a tuned regression lock into an independent detection rate.
"""
import datetime, math, os, pathlib, re, sys

def wilson(k, n):
    if n <= 0: return ("n/a","n/a")
    z=1.96
    p=k/n
    den=1+z*z/n
    center=(p+z*z/(2*n))/den
    half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return (f"{100*(center-half):.1f}%", f"{100*(center+half):.1f}%")
def collect(log, pattern):
    return [m.groups() for line in log.splitlines() if (m:=re.search(pattern,line))]
def table_row(name, a,b,c,d):
    return f"| {name} | {a}/{a+b} | {c}/{c+d} | Development/regression lock, not independent efficacy |"
def main():
    log=pathlib.Path(sys.argv[1]).read_text(errors="replace")
    dst=pathlib.Path(sys.argv[2])
    at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    lines=[
      "# SentinelGuard 4.2 — CI-generated validation summary",
      f"Generated (UTC): {at}",
      f"Commit: `{os.getenv('GITHUB_SHA','local')}`  | GitHub run: `{os.getenv('GITHUB_RUN_ID','local')}`",
      "",
      "**CI-tested, not interactive Windows field-tested.** Nothing in these experiments is real malware.",
      "Stage 6–12/Claude datasets were part of iterative development and are **regression locks**;",
      "100% regression results are not estimates of unseen-malware detection.",
      "",
      "## Established synthetic regression results",
      "| Dataset | Indicators caught | Benign flagged | Evidence class |",
      "|---|---:|---:|---|",
    ]
    groups=[
      ("Stage 6",r"STAGE6_TOTAL\s+tp=(\d+)\s+fn=(\d+)\s+fp=(\d+)\s+tn=(\d+)"),
      ("Stage 9",r"STAGE9_BROAD_TOTAL\s+TP=(\d+)\s+FN=(\d+)\s+FP=(\d+)\s+TN=(\d+)"),
      ("Stage 10 formats",r"STAGE10_FORMATS\s+TP=(\d+)\s+FN=(\d+)\s+FP=(\d+)\s+TN=(\d+)"),
      ("Stage 10 archives",r"STAGE10_ARCHIVES\s+TP=(\d+)\s+FN=(\d+)\s+FP=(\d+)\s+TN=(\d+)"),
      ("Stage 11",r"STAGE11 new-format and behavior cases\s+TP=(\d+)\s+FN=(\d+)\s+FP=(\d+)\s+TN=(\d+)"),
      ("Claude (inert)",r"CLAUDE_V4_TOTAL.*?TP=(\d+)\s+FN=(\d+)\s+FP=(\d+)\s+TN=(\d+)"),
    ]
    for name,pattern in groups:
        found=collect(log,pattern)
        if found:
            a,b,c,d=map(int,found[-1])
            lines.append(table_row(name,a,b,c,d))
        else: lines.append(f"| {name} | Not present in log | Not present in log | No result claimed |")
    lines.extend([
      "",
      "The following Wilson 95% confidence limits describe **sampling uncertainty only**;",
      "they do not compensate for tuned fixtures, non-operational labels or convenience sampling.",
      "",
      "| Data | Reported positive-label rate (Wilson 95%) | Benign flag rate (Wilson 95%) |",
      "|---|---|---|"
    ])
    for name,pattern in (groups[0],groups[-1]):
        found=collect(log,pattern)
        if found:
            tp,fn,fp,tn=map(int,found[-1])
            tlo,thi=wilson(tp,tp+fn)
            flo,fhi=wilson(fp,fp+tn)
            lines.append(f"| {name} | {tp}/{tp+fn} ({tlo}–{thi}) | {fp}/{fp+tn} ({flo}–{fhi}) |")
    lines.extend(["","## Independently sourced benign Windows files (static scan only)",
                  "This is an independent, machine-installed **benign candidate** corpus, not a prevalidated frozen holdout. ",
                  "Flags require human triage; the proportion is a **flag rate**, not a proven false-positive rate.",
                  "",
                  "| Category | Inspected | Flagged | Wilson 95% interval for flag rate | Skipped |",
                  "|---|---:|---:|---|---:|"])
    found=collect(log,r"V42_BENIGN_CORPUS\s+category=(\w+)\s+total=(\d+)\s+flagged=(\d+)\s+skipped=(\d+)")
    for name,n,flagged,skipped in found:
       n,flagged,skipped=int(n),int(flagged),int(skipped)
       lo,hi=wilson(flagged,n)
       lines.append(f"| {name} | {n} | {flagged} | {lo}–{hi} | {skipped} |")
    if not found:lines.append("| Not available | — | — | — | — |")
    lines.extend(["","### Every flagged benign candidate (review, not automatically a false positive)"])
    flagged=[line.partition("V42_BENIGN_FLAG ")[2].strip() for line in log.splitlines() if "V42_BENIGN_FLAG " in line]
    lines.extend(f"- `{s.replace(chr(96),'')}`" for s in flagged)
    if not flagged:lines.append("No flagged entries appeared in the test log.")
    lines.extend(["","## EICAR harmless signature and archive checks",""])
    ec=[line.partition("V42_EICAR ")[2].strip() for line in log.splitlines() if "V42_EICAR " in line]
    lines.extend(f"- `{x}`" for x in ec)
    if not ec:lines.append("No EICAR result in this log.")
    lines.extend(["","## What this CI did **not** test",
       "- No interactive WebView2 window, SmartScreen dialog, actual Windows user clicking Scan & Run approval, or real Firefox/Chrome blocking.",
       "- No real malware was downloaded or executed; no user-run offline VM results are included.",
       "- No independent malicious-sample holdout was obtained. Stage 6/9/10/11 and Claude samples are development fixtures.",
       "- Windows installed files are *candidate* benign samples; human review is required to establish false-positive labels.",
       "- The published EICAR and AMTSO harmless tests do not establish real-world malware detection rates.",
       "",
       "See `docs/COVERAGE_MATRIX_v4.2.md`, the changelog and the isolated-lab runbook for limitations and methodology."
    ])
    dst.parent.mkdir(parents=True,exist_ok=True)
    dst.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print("Generated",dst,len(lines),"sections; Windows benign categories",len(found))
if __name__=="__main__":main()
