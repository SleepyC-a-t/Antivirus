package main

import (
    "regexp"
    "strings"
)

// High-context static rules for inert threat-emulation coverage.
// These are advisory findings, not proof of malware. No payload is executed
// and no network or filesystem side effects occur during inspection.
//
// Server-side web shell rules require an actual server-script extension,
// a script opener, an HTTP request parameter and its use as process/code
// execution input. Plain PHP/ASP.NET/JSP projects are not suspicious by default.
func stage13InspectableExtension(ext string) bool {
    switch ext {
    case ".php", ".phtml", ".php5", ".aspx", ".ashx", ".jsp", ".jspx":
        return true
    }
    return false
}

var stage13BlockComments = regexp.MustCompile(`(?s)/\*.*?\*/`)
var stage13LineComments = regexp.MustCompile(`(?m)(?:^|[;\s])//[^\r\n]*`)
var stage13PHPInput = regexp.MustCompile(`(?i)\$_(?:post|get|request)\s*\[\s*['"][^'"\r\n]{1,96}['"]\s*\]`)
var stage13PHPVariable = regexp.MustCompile(`(?i)\$([a-z_][a-z0-9_]*)\s*=\s*\$_(?:post|get|request)\s*\[`)
var stage13PHPCommand = regexp.MustCompile(`(?i)\b(?:shell_exec|system|exec|passthru)\s*\(`)
var stage13PHPDirect = regexp.MustCompile(`(?is)\b(?:shell_exec|system|exec|passthru)\s*\(\s*\$_(?:post|get|request)\s*\[`)
var stage13PHPEval = regexp.MustCompile(`(?is)\beval\s*\(\s*base64_decode\s*\(\s*\$_(?:post|get|request)\s*\[`)
var stage13ASPXVariable = regexp.MustCompile(`(?i)\b(?:var|string)\s+([a-z_][a-z0-9_]*)\s*=\s*request(?:\.form)?\s*\[`)
var stage13ASPProcessStart = regexp.MustCompile(`(?i)\b(?:system\.diagnostics\.)?process\.start\s*\(`)
var stage13JSPVariable = regexp.MustCompile(`(?i)\b(?:string|var)\s+([a-z_][a-z0-9_]*)\s*=\s*request\.getparameter\s*\(`)
var stage13CertutilRemote = regexp.MustCompile(`(?im)(?:^|[\r\n&])\s*certutil(?:\.exe)?\s+[^\r\n]{0,160}-urlcache\b[^\r\n]{0,200}https?://[^\s"'<>]+\s+([^\s"'<>]+\.(?:exe|cmd|bat|ps1))`)
var stage13BITSRemote = regexp.MustCompile(`(?im)(?:^|[\r\n&])\s*start-bitstransfer\b[^\r\n]{0,220}-source\s+https?://[^\s"'<>]+[^\r\n]{0,220}-destination\s+([^\s"'<>]+\.(?:exe|cmd|bat|ps1))`)
var stage13GetAMSIType = regexp.MustCompile(`(?i)\bgettype\s*\(\s*['"][^'"\r\n]{0,160}amsiutils['"]\s*\)`)
var stage13AMSISet = regexp.MustCompile(`(?i)\$?amsiinitfailed\s*=\s*\$true\b`)

func stage13VisibleSource(src string) string {
    // A lightweight lexical filter, not a language parser. Prevent common
    // comment-only documents from matching; do not attempt dynamic evaluation.
    return stage13LineComments.ReplaceAllString(
        stage13BlockComments.ReplaceAllString(src, ""), "")
}

func stage13ExecOnVariable(src, varName string, commands []string) bool {
    if varName==""{return false}
    lower:=strings.ToLower(src)
    variable:=strings.ToLower(varName)
    for _,command:=range commands {
        pattern:=regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(command)+`\s*\(\s*\$?`+regexp.QuoteMeta(variable)+`\s*\)`)
        if pattern.MatchString(lower){return true}
    }
    return false
}

func stage13DownloadIsLaunched(code, destination string) bool {
    dest:=strings.ToLower(strings.TrimSpace(destination))
    if dest==""{return false}
    for _,line:=range strings.Split(strings.ToLower(code),"\n"){
        line=strings.TrimSpace(line)
        for _,prefix:=range []string{"start ", "call ", "start-process ", "start-process -filepath "} {
            if strings.HasPrefix(line,prefix) && strings.Contains(line[len(prefix):],dest){
                return true
            }
        }
    }
    return false
}

func inspectStage13Content(name,ext string,data []byte,score *int,reasons *[]string){
    if len(data)==0 || len(data)>512*1024{return}
    // Filter before expensive regex work. No binary or unknown-document scan.
    switch ext{
    case ".php",".phtml",".php5",".aspx",".ashx",".jsp",".jspx",
         ".ps1",".psm1",".cmd",".bat":
    default:return
    }
    src:=decodeScriptText(data)
    visible:=stage13VisibleSource(src)
    code:=strings.ToLower(codeOnlyForSignals(src))
    lower:=strings.ToLower(visible)
    add:=func(n int,why string){*score+=n;*reasons=append(*reasons,why)}
    switch ext {
    case ".php",".phtml",".php5":
        if !strings.Contains(lower,"<?php") {return}
        if stage13PHPEval.MatchString(visible){
            add(79,"Web-shell indicator: PHP request data passed into dynamically decoded eval")
            return
        }
        if !stage13PHPInput.MatchString(visible) || !stage13PHPCommand.MatchString(visible) {return}
        if stage13PHPDirect.MatchString(visible){
            add(76,"Web-shell indicator: PHP request parameter directly supplied to command execution")
            return
        }
        for _,match:=range stage13PHPVariable.FindAllStringSubmatch(visible,8){
            if len(match)>=2&&stage13ExecOnVariable(visible,match[1],[]string{"shell_exec","system","exec","passthru"}){
                add(69,"Web-shell indicator: PHP request-derived variable passed to command execution")
                return
            }
        }
    case ".aspx",".ashx":
        if !strings.Contains(lower,"<%")||!stage13ASPProcessStart.MatchString(visible){return}
        for _,match:=range stage13ASPXVariable.FindAllStringSubmatch(visible,8){
            if len(match)>=2&&stage13ExecOnVariable(visible,match[1],[]string{"process.start","system.diagnostics.process.start"}){
                add(73,"Web-shell indicator: ASP.NET request-derived variable starts a process")
                return
            }
        }
    case ".jsp",".jspx":
        if !strings.Contains(lower,"<%"){return}
        for _,match:=range stage13JSPVariable.FindAllStringSubmatch(visible,8){
            if len(match)<2{continue}
            varName:=regexp.QuoteMeta(match[1])
            if regexp.MustCompile(`(?i)runtime\.getruntime\s*\(\s*\)\.exec\s*\(\s*`+varName+`\s*\)`).MatchString(visible) ||
                regexp.MustCompile(`(?i)new\s+processbuilder\s*\(\s*`+varName+`\s*\)\.start\s*\(`).MatchString(visible){
                add(75,"Web-shell indicator: JSP request parameter used to launch a process")
                return
            }
        }
    case ".ps1",".psm1":
        // An isolated BITS transfer is normal administration. Require a
        // remote executable/script destination AND subsequent same-path run.
        for _,match:=range stage13BITSRemote.FindAllStringSubmatch(visible,8){
            if len(match)>=2&&stage13DownloadIsLaunched(visible,match[1]){
                add(63,"PowerShell BITS downloads and launches the same executable/script path")
                break
            }
        }
        // GetType string literal + code assignment to AMSI state. A mere
        // documentation mention or isolated reflection API is insufficient.
        if stage13GetAMSIType.MatchString(visible) &&
            stage13AMSISet.MatchString(code) {
            add(88,"PowerShell reflects into an AMSI-related type and sets a disabling state")
        }
    case ".cmd",".bat":
        // Certutil is used legitimately for administration. Only a remote
        // download followed by a launch of its *same* output path is scored.
        for _,match:=range stage13CertutilRemote.FindAllStringSubmatch(visible,8){
            if len(match)>=2&&stage13DownloadIsLaunched(visible,match[1]){
                add(71,"Command script uses certutil to retrieve and then launch the same executable/script")
                return
            }
        }
    }
    _=name
}
