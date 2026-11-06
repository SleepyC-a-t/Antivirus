package main

import (
    "regexp"
    "strings"
)

// Stage 11 high-context triage. These signatures are advisory; the scanner
// never launches source, follows remote links, or executes file contents.
func stage11InspectableExtension(ext string) bool {
    switch ext {
    case ".scf",".inf",".svg",".hta",".vbs",".vbe",".ps1",".psm1",".bat",".cmd",".html",".htm":
        return true
    }
    return false
}

var stage11SVGScript=regexp.MustCompile(`(?is)<script\b[^>]{0,300}>[\s\S]*?</script\s*>`)
var stage11ShellDownload=regexp.MustCompile(`(?is)\binvoke-(?:webrequest|restmethod)\b[\s\S]{0,450}-(?:outfile|output)\b[\s\S]{0,500}\bstart-process\b`)
var stage11SCFHeader=regexp.MustCompile(`(?im)^\s*\[shell\]\s*$`)

func stage11INIValue(src, section, key string) string {
    active:=""
    for _,line:=range strings.Split(strings.ReplaceAll(src,"\r\n","\n"),"\n") {
        s:=strings.TrimSpace(line)
        if s=="" || strings.HasPrefix(s,";") || strings.HasPrefix(s,"#"){continue}
        if strings.HasPrefix(s,"[") && strings.HasSuffix(s,"]") {
            active=strings.ToLower(strings.TrimSpace(s[1:len(s)-1]))
            continue
        }
        if active!=section {continue}
        parts:=strings.SplitN(s,"=",2)
        if len(parts)==2 && strings.EqualFold(strings.TrimSpace(parts[0]),key) {
            return strings.TrimSpace(parts[1])
        }
    }
    return ""
}

func inspectStage11Content(name,ext string,data []byte,score *int,reasons *[]string) {
    if len(data)==0 || len(data)>2*1024*1024{return}
    src:=decodeScriptText(data)
    lower:=strings.ToLower(src)
    add:=func(points int,why string){*score+=points;*reasons=append(*reasons,why)}
    switch ext {
    case ".scf":
        // Shell command files can request remote UNC icons. This is an
        // NTLM credential-exposure indicator, not arbitrary code execution.
        if !stage11SCFHeader.MatchString(src) {return}
        icon:=strings.ToLower(stage11INIValue(src,"shell","IconFile"))
        if icon=="" {icon=strings.ToLower(stage11INIValue(src,"taskbar","IconFile"))}
        if (strings.HasPrefix(icon,`\\`) || strings.HasPrefix(icon,"//")) &&
            (stage11INIValue(src,"shell","Command")!="" || stage11INIValue(src,"taskbar","Command")!="") {
            add(66,"Shell Command File requests an icon from a remote network share (possible credential exposure)")
        }
    case ".inf":
        // Autorun is disabled for many removable drives on modern Windows;
        // this is a suspicious artifact, not evidence of execution.
        command:=strings.ToLower(stage11INIValue(src,"autorun","open"))
        if command=="" {command=strings.ToLower(stage11INIValue(src,"autorun","shellexecute"))}
        if command=="" {return}
        if (strings.Contains(command,"powershell") || strings.Contains(command,"mshta") ||
            strings.Contains(command,"wscript") || strings.Contains(command,"cmd.exe")) &&
            (strings.Contains(command,"-enc") || strings.Contains(command,"http") ||
             strings.Contains(command,".ps1") || strings.Contains(command,"/c ") ||
             strings.Contains(command,".hta")) {
            add(72,"Autorun instructions launch a script interpreter with risky arguments (execution may be blocked by Windows)")
        }
    case ".svg":
        // Static SVG graphics and ordinary SVG icons remain clean.
        if !strings.Contains(lower,"<svg") || !stage11SVGScript.MatchString(src) {return}
        if (strings.Contains(lower,"eval(") && strings.Contains(lower,"fetch(")) ||
           (strings.Contains(lower,"atob(") && strings.Contains(lower,"function(") && strings.Contains(lower,"http")) {
            add(78,"SVG image includes active script that retrieves and executes/decodes remote content")
        }
    case ".html",".htm":
        // HTML smuggling is also used legitimately to export generated data:
        // require a combination of encoded payload and forced file download.
        if strings.Contains(lower,"atob(") && strings.Contains(lower,"new blob(") &&
            strings.Contains(lower,"createobjecturl(") && strings.Contains(lower,".click(") {
            add(58,"HTML constructs and downloads a file from decoded data (potential HTML smuggling)")
        }
    case ".vbs",".vbe":
        if strings.Contains(lower,"msxml2.xmlhttp") && strings.Contains(lower,"adodb.stream") &&
            strings.Contains(lower,"wscript.shell") {
            code:=strings.ToLower(codeOnlyForSignals(src))
            if strings.Contains(code,".open(") && strings.Contains(code,".send(") &&
               strings.Contains(code,".savetofile(") && strings.Contains(code,".run(") {
                add(88,"VBScript downloads a payload, saves it to disk, and launches it")
            }
        }
    case ".ps1",".psm1":
        code:=strings.ToLower(codeOnlyForSignals(src))
        if strings.Contains(lower,"http") && stage11ShellDownload.MatchString(code) &&
           (strings.Contains(lower,".exe") || strings.Contains(lower,".ps1") || strings.Contains(lower,".cmd")) {
            add(56,"PowerShell downloads a file and then launches a process (review source and destination)")
        }
    }
    _=name
}
