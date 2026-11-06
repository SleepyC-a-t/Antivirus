package main

import (
	"regexp"
	"strings"
)

// SentinelGuard v2.1: checks that require syntactic proximity and a
// compatible execution format. This deliberately avoids treating arbitrary
// strings in minified, multi-megabyte JavaScript bundles as executable
// commands. These are static indicators, not definitive malware verdicts.
func stage8ContextualRule(label string) bool {
	switch label {
	case "Downloads source content and executes it in Python",
		"Pipes remotely downloaded data to a shell",
		"Downloads a remote script through an XMLHTTP object",
		"Queries DNS with a variable subdomain",
		"Uses a remote PsExec command":
		return true
	}
	return false
}

var stage8PythonExec = regexp.MustCompile(`(?i)\bexec\s*\([\s\S]{0,350}\burlopen\s*\([\s\S]{0,350}\.read\s*\(\s*\)`)
var stage8ShellPipe = regexp.MustCompile(`(?i)\b(?:curl|wget)(?:\.exe)?\b[^\r\n]{0,350}\|\s*(?:sh|bash)(?:\s|$|[;&])`)
var stage8XMLHTTP = regexp.MustCompile(`(?i)\bcreateobject\s*\([^\r\n]{0,100}xmlhttp[^\r\n]{0,250}\.\s*open\b`)
var stage8PsExec = regexp.MustCompile(`(?i)(?:^|[\r\n&;])\s*(?:[^\r\n]{0,120}[\s])?psexec(?:\.exe)?\s+\\\\[^\s\\]+`)
var stage8DNS = regexp.MustCompile(`(?i)\bnslookup(?:\.exe)?\s+(?:\$\{?[a-z_][a-z0-9_]*\}?|%[a-z_][a-z0-9_]*%|\$[a-z_][a-z0-9_]*\.)[^\r\n]{0,160}`)

func inspectStage8Context(source, ext string, score *int, reasons *[]string) {
	// Strip non-executing comments and quoted examples before looking for a
	// leading command. Certain signatures use string arguments as parameters
	// and therefore examine raw text only after checking the command type.
	lower := strings.ToLower(source)
	if ext==".py" && strings.Contains(lower,"exec(") && strings.Contains(lower,"urlopen(") &&
		stage8PythonExec.MatchString(lower) {
		*score+=86
		*reasons=append(*reasons,"In-memory execution: downloads and executes Python source in one expression")
	}
	if (ext==".sh" || ext==".bash" || ext==".cmd" || ext==".bat" || ext==".ps1") &&
		strings.Contains(lower,"curl") && stage8ShellPipe.MatchString(strings.ToLower(codeOnlyForSignals(source))) {
		*score+=82
		*reasons=append(*reasons,"Shell execution: download piped to a shell on the same command line")
	}
	// Windows Script Host/VBScript supports CreateObject("MSXML2.XMLHTTP").
	// Ordinary Office/Node JavaScript bundles use XMLHTTP for legitimate I/O;
	// scanning for CreateObject, xmlhttp and .open anywhere in such files
	// generated many false positives.
	if (ext==".vbs" || ext==".vbe" || ext==".wsf" || ext==".hta") &&
		stage8XMLHTTP.MatchString(lower) {
		*score+=59
		*reasons=append(*reasons,"Script execution: creates XMLHTTP object and opens a request in a single statement")
	}
	if (ext==".ps1" || ext==".psm1" || ext==".cmd" || ext==".bat" || ext==".sh") &&
		strings.Contains(lower,"nslookup") && stage8DNS.MatchString(strings.ToLower(codeOnlyForSignals(source))) {
		*score+=43
		*reasons=append(*reasons,"Network behavior: dynamically constructed DNS lookup in a command")
	}
	if (ext==".cmd" || ext==".bat" || ext==".ps1" || ext==".psm1" || ext==".sh") &&
		strings.Contains(lower,"psexec") && stage8PsExec.MatchString(strings.ToLower(codeOnlyForSignals(source))) {
		*score+=58
		*reasons=append(*reasons,"Lateral movement: PsExec command targeting a remote host")
	}
}
