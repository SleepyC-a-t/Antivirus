package main

import (
    "sort"
    "strings"
)

// FindingReasonSummary is an aggregate diagnostic to help identify groups of
// heuristic alerts. It intentionally omits file names, absolute paths,
// hashes, content and per-item identifiers. Counts are not malware verdicts.
type FindingReasonSummary struct {
    RuleFamily string `json:"ruleFamily"`
    Findings int `json:"findings"`
    HighestScore int `json:"highestScore"`
}

// The scanner currently exposes natural-language heuristic reasons rather
// than stable rule IDs. Use deliberately broad, stable families instead of
// embedding source/archive entry filenames in an aggregate report.
func reasonFamily(reason string) string {
    s:=strings.ToLower(reason)
    switch {
    case strings.Contains(s,"archive") || strings.Contains(s,"zip"):
        return "Archive content or filename"
    case strings.Contains(s,"pdf"):
        return "PDF action or structure"
    case strings.Contains(s,"macro") || strings.Contains(s,"office"):
        return "Office macro or document"
    case strings.Contains(s,"pe import") || strings.Contains(s,"entropy") ||
         strings.Contains(s,"authenticode") || strings.Contains(s,"packer") || strings.Contains(s,"pe overlay"):
        return "PE metadata and imports"
    case strings.Contains(s,"double extension") || strings.Contains(s,"disguised executable") ||
         strings.Contains(s,"bidi") || strings.Contains(s,"bidirectional") ||
         strings.Contains(s,"masquerad") || strings.Contains(s,"filename"):
        return "Filename or format mismatch"
    case strings.Contains(s,"startup") || strings.Contains(s,"registry") ||
         strings.Contains(s,"scheduled task") || strings.Contains(s,"persist"):
        return "Startup or persistence"
    case strings.Contains(s,"script") || strings.Contains(s,"powershell") ||
         strings.Contains(s,"command interpreter") || strings.Contains(s,"javascript") ||
         strings.Contains(s,"msiexec"):
        return "Script or command execution"
    case strings.Contains(s,"ransom") || strings.Contains(s,"encrypted") || strings.Contains(s,"locked"):
        return "Ransomware-related indicator"
    case strings.Contains(s,"credential") || strings.Contains(s,"cookies") || strings.Contains(s,"wallet"):
        return "Credential access or exfiltration"
    case strings.Contains(s,"remote") || strings.Contains(s,"download") ||
         strings.Contains(s,"url") || strings.Contains(s,"network") ||
         strings.Contains(s,"webhook") || strings.Contains(s,"dns"):
        return "Network or remote content"
    case strings.Contains(s,"invoice") || strings.Contains(s,"document") ||
         strings.Contains(s,"text"):
        return "Document or text advisory"
    default:
        return "Other heuristic indicator"
    }
}

// A finding may have several independent reasons, but it counts at most
// once per family. Empty/no-reason findings remain visible as "Unspecified".
func summarizeFindingReasons(findings []Finding) []FindingReasonSummary {
    byFamily:=make(map[string]*FindingReasonSummary)
    for _,finding:=range findings {
        seen:=make(map[string]bool)
        if len(finding.Reasons)==0{seen["Unspecified"]=true}
        for _,why:=range finding.Reasons {
            family:=reasonFamily(why)
            seen[family]=true
        }
        for family:=range seen{
            row:=byFamily[family]
            if row==nil{
                row=&FindingReasonSummary{RuleFamily:family}
                byFamily[family]=row
            }
            row.Findings++
            if finding.Score>row.HighestScore{row.HighestScore=finding.Score}
        }
    }
    result:=make([]FindingReasonSummary,0,len(byFamily))
    for _,row:=range byFamily{result=append(result,*row)}
    sort.Slice(result,func(i,j int)bool{
        if result[i].Findings==result[j].Findings{
            return result[i].RuleFamily<result[j].RuleFamily
        }
        return result[i].Findings>result[j].Findings
    })
    return result
}
