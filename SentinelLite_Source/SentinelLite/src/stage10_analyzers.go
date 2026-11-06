package main

import (
	"regexp"
	"strings"
)

// Stage 10 adds bounded recognition for active Windows Script Host packages
// (.wsf, .sct) and remote-executable Windows Internet Shortcuts (.url).
// These are advisory patterns, not proofs of malware. No file is executed.
func stage10InspectableExtension(ext string) bool {
	switch ext {
	case ".wsf", ".sct", ".url":
		return true
	}
	return false
}

var stage10XMLComments = regexp.MustCompile(`(?s)<!--.*?-->`)
var stage10ScriptBlock = regexp.MustCompile(`(?is)<script\b[^>]{0,300}>([\s\S]*?)</script\s*>`)
var stage10WSHCreate = regexp.MustCompile(`(?i)\b(?:new\s+activexobject|(?:wscript\.)?createobject)\s*\(\s*['"]wscript\.shell['"]\s*\)`)
var stage10WSHRun = regexp.MustCompile(`(?i)\.\s*run\s*\(`)
var stage10WSHInterpreter = regexp.MustCompile(`(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|mshta(?:\.exe)?|wscript(?:\.exe)?)\b`)
var stage10WSHHighRiskArgument = regexp.MustCompile(`(?i)(?:\s-(?:enc(?:odedcommand)?|nop(?:rofile)?|w(?:indowstyle)?\s+hidden)\b|\bhttps?://|\binvoke-expression\b|\bdownloadstring\b)`)

func inspectStage10Content(name, ext string, data []byte, score *int, reasons *[]string) {
	// The common scanner calls this on many PE and script files. Return
	// before Unicode decoding or regex work for irrelevant extensions.
	if !stage10InspectableExtension(ext) || len(data)==0 || len(data)>512*1024 {return}
	src:=decodeScriptText(data)
	lower:=strings.ToLower(src)
	switch ext {
	case ".wsf", ".sct":
		// Not arbitrary HTML or XML documentation. Recognize script elements
		// inside Windows Script Host packages or registered scriptlets.
		if ext==".wsf" && !(strings.Contains(lower,"<job") || strings.Contains(lower,"<package")) {return}
		if ext==".sct" && !strings.Contains(lower,"<scriptlet") {return}
		src=stage10XMLComments.ReplaceAllString(src,"")
		for _,match:=range stage10ScriptBlock.FindAllStringSubmatch(src,8) {
			code:=strings.TrimSpace(match[1])
			if strings.HasPrefix(code,"<![CDATA[") {code=strings.TrimPrefix(code,"<![CDATA[")}
			code=strings.TrimSuffix(strings.TrimSpace(code),"]]>")
			if len(code)==0 {continue}
			// The lexical filter drops comments and quoted arguments. Require
			// actual object construction and invocation in the remaining code.
			visible:=strings.ToLower(codeOnlyForSignals(code))
			if (!strings.Contains(visible,"createobject(") && !strings.Contains(visible,"activexobject(")) ||
				!stage10WSHRun.MatchString(visible) || !stage10WSHCreate.MatchString(code) {continue}
			if !stage10WSHInterpreter.MatchString(code) || !stage10WSHHighRiskArgument.MatchString(code) {continue}
			*score+=83
			*reasons=append(*reasons,"Windows Script Host package launches a script interpreter with high-risk arguments")
			return
		}
	case ".url":
		// Ordinary HTTP and HTTPS shortcuts are NOT suspicious. This only
		// reviews UNC-style executable targets, not everyday web bookmarks.
		if len(src)>64*1024 {return}
		inShortcut:=false
		for _,line:=range strings.Split(strings.ReplaceAll(src,"\r\n","\n"),"\n") {
			s:=strings.TrimSpace(line)
			if s=="" || strings.HasPrefix(s,";") || strings.HasPrefix(s,"#") {continue}
			if strings.HasPrefix(s,"[") && strings.HasSuffix(s,"]") {
				inShortcut=strings.EqualFold(s,"[InternetShortcut]")
				continue
			}
			if !inShortcut {continue}
			kv:=strings.SplitN(s,"=",2)
			if len(kv)!=2 || !strings.EqualFold(strings.TrimSpace(kv[0]),"URL") {continue}
			v:=strings.ToLower(strings.TrimSpace(kv[1]))
			// UNC network share executed through a file URI. Local file
			// bookmarks and regular web links remain benign.
			if (strings.HasPrefix(v,"file:////") || strings.HasPrefix(v,"file://")) &&
				(strings.HasSuffix(v,".exe") || strings.HasSuffix(v,".scr") || strings.HasSuffix(v,".hta")) &&
				(strings.Contains(v,"/share/") || strings.Contains(v,"/public/") ||
				strings.Contains(v,"%5c%5c")) {
				*score+=54
				*reasons=append(*reasons,"Internet Shortcut points to an executable on a remote file share (review destination)")
				return
			}
		}
	}
	_ = name
}
