#!/usr/bin/env python3
"""Fetch pinned public technique *descriptions* for static scanning; NEVER execute.
The generated files live exclusively in a temporary GitHub Actions directory.
Do not re-publish the upstream definitions; cite their source and license.
"""
from __future__ import annotations
import hashlib,json,pathlib,re,sys,urllib.request

ATOMIC="a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
LOLBAS="2056cb7662509dc998fc6ce79636aec4e6c0397f"
SOURCES=[
 ("Atomic-PS","redcanaryco/atomic-red-team",ATOMIC,"atomics/T1059.001/T1059.001.yaml"),
 ("Atomic-CMD","redcanaryco/atomic-red-team",ATOMIC,"atomics/T1059.003/T1059.003.yaml"),
 ("LOLBAS-certutil","LOLBAS-Project/LOLBAS",LOLBAS,"yml/OSBinaries/Certutil.yml"),
 ("LOLBAS-mshta","LOLBAS-Project/LOLBAS",LOLBAS,"yml/OSBinaries/Mshta.yml"),
 ("LOLBAS-regsvr32","LOLBAS-Project/LOLBAS",LOLBAS,"yml/OSBinaries/Regsvr32.yml"),
]
def blocks(text):
    # Conservative multiline command-field reader; not a full YAML parser.
    lines=text.splitlines()
    found=[]
    for i,line in enumerate(lines):
        match=re.match(r"^(\s+)(?:command|Command):\s*(?:\||>)\s*$",line)
        if match:
            indent=len(match.group(1))
            parts=[]
            for follow in lines[i+1:]:
                if follow.strip() and len(follow)-len(follow.lstrip())<=indent:break
                parts.append(follow.strip())
            code="\n".join(parts).strip()
            if len(code)>12 and len(code)<20000:found.append(code)
        else:
            match=re.match(r"^\s+Command:\s*['\"]?(.*?)['\"]?\s*$",line)
            if match and len(match.group(1))>12:
                found.append(match.group(1))
    return found[:8]
def main(root):
    out=pathlib.Path(root);out.mkdir(parents=True,exist_ok=True)
    records=[]
    for label,repo,commit,path in SOURCES:
        url=f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"SentinelGuard-v42-static-eval"}),timeout=12) as res:
                data=res.read(400_000)
            if len(data)>300_000:raise ValueError("upstream file too large")
            corpus=blocks(data.decode("utf-8"))
            for i,sample in enumerate(corpus):
                ext=".ps1" if label=="Atomic-PS" else ".cmd"
                name=f"holdout-{label}-{i:02d}{ext}"
                content=sample.encode("utf-8")
                (out/name).write_bytes(content)
                records.append({"file":name,"category":label,"source":url,"source_sha256":hashlib.sha256(data).hexdigest(),
                                "sample_sha256":hashlib.sha256(content).hexdigest(),"label":"technique-example-not-validated-malware"})
        except Exception as exc:
            print("V42_TECHNIQUE_SOURCE_UNAVAILABLE",label,str(exc))
    (out/"manifest.json").write_text(json.dumps(records,indent=2))
    print("V42_TECHNIQUE_SOURCES",len(records),"extracted read-only; NO CODE EXECUTED")
if __name__=="__main__":main(sys.argv[1])
