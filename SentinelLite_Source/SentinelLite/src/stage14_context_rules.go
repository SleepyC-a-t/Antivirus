package main

import (
    "regexp"
    "strings"
)

// Stage 14: confidence checks for weak, cross-file source indicators.
// These predicates never execute inspected content. A filename, institution,
// package name, hash, or fixed allowlist is never used as a trust signal.
// We retain positive detection of linked behaviors while avoiding hits from
// unrelated API references scattered through large scripts and web bundles.

var stage14PySocketAssign = regexp.MustCompile("(?m)(?:^|\\n)[ \\t]*([a-zA-Z_][a-zA-Z0-9_]*)[ \\t]*=[ \\t]*socket\\.socket[ \\t]*\\(")
var stage14PyHexAssign = regexp.MustCompile("(?m)(?:^|\\n)[ \\t]*([a-zA-Z_][a-zA-Z0-9_]*)[ \\t]*=[ \\t]*[a-zA-Z_][a-zA-Z0-9_]*\\.hex[ \\t]*\\(")
var stage14ForLoop = regexp.MustCompile("(?m)\\bfor[ \\t]+[a-zA-Z_][a-zA-Z0-9_]*[ \\t]+in[ \\t]+[^\\r\\n]{1,180}:")
var stage14PyInjectionNames = []*regexp.Regexp{
    regexp.MustCompile("(?i)\\bvirtualalloc(?:ex)?[ \\t]*\\("),
    regexp.MustCompile("(?i)\\bwriteprocessmemory[ \\t]*\\("),
    regexp.MustCompile("(?i)\\bcreateremotethread[ \\t]*\\("),
}
var stage14InlineScript = regexp.MustCompile("(?is)<script\\b[^>]{0,800}>(.*?)</script[ \\t]*>")
var stage14IEXDownload = regexp.MustCompile("(?i)\\b(?:iex|invoke-expression)[ \\t]*\\(?[^\\r\\n]{0,500}\\b(?:downloadstring|downloaddata|downloadfile)[ \\t]*\\(")
var stage14DownloadedPipeIEX = regexp.MustCompile("(?i)\\b(?:invoke-webrequest|invoke-restmethod)[^\\r\\n]{0,500}\\|[ \\t]*(?:iex|invoke-expression)\\b")
var stage14DownloadCmdSameLine = regexp.MustCompile("(?i)\\b(?:downloadstring|downloaddata|downloadfile)[ \\t]*\\([^\\r\\n]{0,400}\\|[ \\t]*(?:iex|invoke-expression)\\b")

func stage14PythonActiveInjection(src string) bool {
    code := codeOnlyForSignals(src)
    locations := make([][][]int, 3)
    for i, r := range stage14PyInjectionNames {
        locations[i] = r.FindAllStringIndex(code, 64)
        if len(locations[i]) == 0 { return false }
    }
    // Real call sites, not three separate API names somewhere in a large
    // source tree. Allow the calls in any order within one bounded routine.
    for _, a := range locations[0] {
        for _, b := range locations[1] {
            if absStage14(a[0]-b[0]) > 4096 { continue }
            for _, c := range locations[2] {
                lo, hi := a[0], a[0]
                for _, p := range []int{b[0], c[0]} {
                    if p < lo { lo=p }; if p > hi { hi=p }
                }
                if hi-lo <= 4096 { return true }
            }
        }
    }
    return false
}
func absStage14(v int) int { if v < 0 {return -v}; return v }

func stage14PythonRemoteCommand(src string) bool {
    code := strings.ToLower(codeOnlyForSignals(src))
    for _, m := range stage14PySocketAssign.FindAllStringSubmatchIndex(code,32) {
        if len(m)<4 {continue}
        obj:=code[m[2]:m[3]]
        upper:=m[0]+4096
        if upper>len(code){upper=len(code)}
        section:=code[m[0]:upper]
        conn:=strings.Index(section,obj+".connect(")
        recv:=strings.Index(section,obj+".recv(")
        run:=strings.Index(section,"subprocess.run(")
        if run<0 {run=strings.Index(section,"subprocess.popen(")}
        send:=strings.Index(section,obj+".send(")
        if send<0 {send=strings.Index(section,obj+".sendall(")}
        if conn>=0 && recv>conn && run>recv && send>run {
            response:=section[run:send]
            output:=section[send:]
            if strings.Contains(response,".stdout") || strings.Contains(output,".stdout") ||
               strings.Contains(response,".communicate(") || strings.Contains(output,".communicate(") {
                return true
            }
        }
    }
    return false
}

func stage14PythonEncodedDNS(src string) bool {
    code := strings.ToLower(codeOnlyForSignals(src))
    for _, loop := range stage14ForLoop.FindAllStringIndex(code,48) {
        start:=loop[0]
        end:=start+1800
        if end>len(code) {end=len(code)}
        segment:=code[start:end]
        resolver:=strings.Index(segment,"socket.gethostbyname(")
        if resolver<0 { resolver=strings.Index(segment,"socket.getaddrinfo(") }
        if resolver<0 {continue}
        if strings.Contains(segment[resolver:],".hex(") {return true}
        for _,match:=range stage14PyHexAssign.FindAllStringSubmatchIndex(segment[:resolver],24) {
            if len(match)<4 {continue}
            label:=segment[match[2]:match[3]]
            target:=segment[resolver:]
            if strings.Contains(target,"("+label+" +") ||
                strings.Contains(target,"("+label+"+") ||
                strings.Contains(target,"("+label+",") {
                return true
            }
        }
    }
    return false
}

func stage14HTMLDecodedAutoDownload(src string) bool {
    for _, block:=range stage14InlineScript.FindAllStringSubmatch(src,64) {
        if len(block)<2 {continue}
        code:=strings.ToLower(codeOnlyForSignals(block[1]))
        if strings.Contains(code,"atob(") && strings.Contains(code,"new blob(") &&
           strings.Contains(code,"createobjecturl(") && strings.Contains(code,".click(") {
            return true
        }
    }
    return false
}

func stage14DirectInterpreterDownloadExecution(code,ext string) bool {
    // Pure JavaScript bundles containing scattered PowerShell identifiers are
    // not PowerShell commands; their own eval(fetch()) detector remains active.
    switch ext {
    case ".ps1",".psm1",".cmd",".bat",".hta",".wsf",".vbs",".vbe":
        return stage14IEXDownload.MatchString(code) ||
            stage14DownloadedPipeIEX.MatchString(code) ||
            stage14DownloadCmdSameLine.MatchString(code)
    default:
        return false
    }
}
