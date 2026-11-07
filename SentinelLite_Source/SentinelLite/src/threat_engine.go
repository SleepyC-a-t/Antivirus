package main

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
)

// SentinelGuard v2.1: rule-based threat behavior triage.
// Signals are not a verdict that a file is malicious. Every finding must be
// reviewed before quarantine. Inspecting a file NEVER executes its content.
type threatRule struct {
	category string
	label    string
	score    int
	require  []string
	any      []string
}

var threatRules = []threatRule{
	{"Defense evasion", "Disables recovery by deleting volume shadow copies", 84, []string{"vssadmin", "delete", "shadows"}, nil},
	{"Defense evasion", "Changes boot recovery configuration", 74, []string{"bcdedit", "recoveryenabled", "no"}, nil},
	{"Defense evasion", "Deletes the backup catalog", 75, []string{"wbadmin", "delete", "catalog"}, nil},
	{"Persistence", "Creates a Windows service", 58, []string{"sc", "create", "binpath"}, nil},
	{"Persistence", "Registers an event-based WMI subscription", 48, []string{"register-wmievent", "query"}, nil},
	{"Lateral movement", "Invokes a remote WMI process", 67, []string{"wmic", "/node:", "process", "create"}, nil},
	{"Lateral movement", "Uses a remote PsExec command", 58, []string{"psexec", "\\\\"}, nil},
	{"Persistence", "Changes Remote Desktop access configuration", 53, []string{"reg add", "fdenytsconnections", "/d 0"}, nil},
	{"Script execution", "Uses regsvr32 to retrieve a remote scriptlet", 85, []string{"regsvr32", "scrobj.dll", "/i:http"}, nil},
	{"Script execution", "Launches a JavaScript engine through rundll32", 84, []string{"rundll32", "javascript:", "mshtml"}, nil},
	{"Script execution", "Runs a silent installer from a remote URL", 60, []string{"msiexec", "http"}, []string{"/qn", "/quiet"}},
	{"Script execution", "Uses BITSAdmin to transfer remote content", 54, []string{"bitsadmin", "/transfer", "http"}, nil},
	{"Credential access", "Requests an LSASS process memory dump", 98, []string{"procdump", "lsass", "-ma"}, nil},
	{"Credential access", "References browser credential database extraction", 57, []string{"login data", "copy-item"}, nil},
	{"Credential access", "Calls the Windows DPAPI decryption API", 43, []string{"protecteddata", "unprotect"}, nil},
	{"Exfiltration", "Posts a local file over HTTP from a script", 67, []string{"invoke-restmethod", "-method post", "-infile"}, nil},
	{"Exfiltration", "Uploads a local file using curl form submission", 60, []string{"curl", "-f", "file=@"}, nil},
	{"Exfiltration", "Queries DNS with a variable subdomain", 43, []string{"nslookup", "$"}, nil},
	{"Exfiltration", "Reads clipboard and saves it to a file", 46, []string{"get-clipboard", "out-file"}, nil},
	{"Execution", "Downloads a remote script through an XMLHTTP object", 59, []string{"createobject(", "xmlhttp", ".open"}, nil},
	{"Defense evasion", "Attempts to disable PowerShell AMSI scanning", 100, []string{"amsiutils", "amsiinitfailed"}, nil},
	{"In-memory execution", "Contains a process-injection API sequence", 95, []string{"virtualalloc", "writeprocessmemory", "createremotethread"}, nil},
	{"In-memory execution", "Contains a process-hollowing API sequence", 88, []string{"ntunmapviewofsection", "resumethread"}, nil},
	{"In-memory execution", "Downloads source content and executes it in Python", 86, []string{"exec(", "urlopen(", ".read()"}, nil},
	{"In-memory execution", "Pipes remotely downloaded data to a shell", 82, []string{"curl", "| sh"}, nil},
	{"Ransomware behavior", "Bulk-renames files to a suspicious encrypted-looking extension", 54, []string{"get-childitem", "rename-item", ".locked"}, nil},
}

var ruleSpace = regexp.MustCompile(`\s+`)
var remoteURL = regexp.MustCompile(`(?i)https?://`)
var htmlPasswordForm = regexp.MustCompile(`(?i)<form\b[\s\S]{0,900}password`)

var threatQuickKeywords = [...]string{
	"vssadmin","bcdedit","wbadmin","sc create","register-wmievent","wmic",
	"psexec","reg add","regsvr32","rundll32","msiexec","bitsadmin",
	"procdump","copy-item","protecteddata","invoke-restmethod","curl",
	"nslookup","get-clipboard","createobject(","amsiutils","virtualalloc",
	"ntunmapviewofsection","exec(","get-childitem","voke-expression","assembly]::load",
}
func hasThreatIndicators(raw string) bool {
	for _, token := range threatQuickKeywords {
		if strings.Contains(raw,token) {return true}
	}
	return false
}

func inspectThreatBehavior(data []byte, ext string, score *int, reasons *[]string) {
	if len(data)==0 {return}
	// HTML has its own conservative, low-confidence form check.
	if ext==".html" || ext==".htm" {
		if htmlPasswordForm.Match(data) && remoteURL.Match(data) {
			*score+=40
			*reasons=append(*reasons,"Web content: password form with a remote destination (could be legitimate)")
		}
		return
	}
	if !isThreatScriptExtension(ext) {return}
	decoded:=decodeScriptText(data)
	raw:=strings.ToLower(decoded)
	// Most files contain none of the behavior indicators. Skip costly lexical
	// normalization for those files; still inspect every matching file below.
	if !hasThreatIndicators(raw) {return}
	code:=strings.ToLower(codeOnlyForSignals(decoded))
	flat := ruleSpace.ReplaceAllString(code, " ")
	flatRaw := ruleSpace.ReplaceAllString(raw, " ")
	for _, rule := range threatRules {
		// Stage 12: require a direct same-command remote MSI target.
        // A URL elsewhere plus a local silent installer is not sufficient.
        if rule.label=="Runs a silent installer from a remote URL" {continue}
		// These five v2.0 checks produced 114 of 158 false-positive
		// candidates in the observed clean-machine scan. Stage 8 evaluates
		// them as tightly scoped command patterns, not unrelated substrings.
		if stage8ContextualRule(rule.label) {continue}
		// Restrict rules to executable / script-like files, not static prose.
		if !isThreatScriptExtension(ext) {continue}
		// Evaluate code tokens; some commands embed important parameters in
		// quoted strings, so require at least one invocation in code first.
		text := flat
		if rule.category == "Credential access" || rule.category == "Execution" || rule.category == "In-memory execution" ||
			rule.category == "Script execution" || rule.category == "Exfiltration" || rule.category=="Ransomware behavior" {
			if len(code) < 4 {continue}
			// Use raw only where code includes the leading command identifier.
			if strings.Contains(code, rule.require[0]) {text=flatRaw}
		}
		matched:=true
		for _, required:=range rule.require {
			if !strings.Contains(text,required) {matched=false;break}
		}
		if matched && len(rule.any)>0 {
			matched=false
			for _, option:=range rule.any {if strings.Contains(text,option){matched=true;break}}
		}
		if matched {
			*score+=rule.score
			*reasons=append(*reasons, rule.category+": "+rule.label)
		}
	}
	inspectStage8Context(decoded,ext,score,reasons)
	// Suspiciously reconstructed command names matter when immediately invoked.
	// Concatenation alone, especially in a quotation or example, is insufficient.
	if ext==".ps1" || ext==".psm1" {
		reassembled:=regexp.MustCompile(`(?i)['"]in['"]\s*\+\s*['"]voke-expression['"]`)
		if reassembled.MatchString(decoded) && regexp.MustCompile(`(?i)&\s*\$[a-z_][a-z0-9_]*`).MatchString(decoded) {
			*score+=68
			*reasons=append(*reasons,"Script execution: reconstructs and invokes an interpreter command")
		}
	}

}

func isThreatScriptExtension(ext string) bool {
	switch ext {
	case ".ps1",".psm1",".bat",".cmd",".vbs",".vbe",".js",".jse",".hta",".wsf",".py",".sh":
		return true
	}
	return false
}

// Format validation for an executable image, not a signature for malware.
func inspectPEFileMetadata(buf []byte, ext string, score *int, reasons *[]string) {
	if len(buf)<256 || !isPEHeader(buf) {return}
	if ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".com" && ext != ".cpl" {return}
	offset:=int(binary.LittleEndian.Uint32(buf[0x3c:0x40]))
	if offset+24>len(buf){return}
	sections:=int(binary.LittleEndian.Uint16(buf[offset+6:offset+8]))
	if sections>24 {
		// An unusually high section count is not independently malicious.
		// It is common in legitimate kernels and device drivers. Only
		// corroborating suspicious signals should elevate the file.
		*score+=12
		*reasons=append(*reasons, "PE metadata: unusually large section count (weak signal only)")
	}
	// We intentionally do not flag high entropy or ordinary unsigned
	// executables: both commonly occur in legitimate software.
}

// Treat an encoded command in a valid Windows .lnk as a signal, but don't
// confuse a plaintext example with a shortcut file.
func inspectValidatedShortcut(buf []byte, score *int, reasons *[]string) {
	if len(buf)<76 || binary.LittleEndian.Uint32(buf[:4])!=0x4c {return}
	// Standard Shell Link CLSID as serialized in a .lnk file.
	clsid:=[]byte{0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}
	if !bytes.Equal(buf[4:20],clsid){return}
	if inspectStructuredShortcut(buf,score,reasons){return}
    inspectShortcut(buf, score, reasons)
}


// A ransom note is evidence worth showing, but not proof a ransomware
// executable was present or active. Require both a recovery-themed filename
// and extortion language; ordinary encryption documentation is ignored.
func inspectRansomNote(name string, data []byte, score *int, reasons *[]string) {
 lowerName:=strings.ToLower(name)
 if !(strings.Contains(lowerName,"decrypt") || strings.Contains(lowerName,"recover_files") || strings.Contains(lowerName,"readme_recover")) {return}
 text:=strings.ToLower(string(data))
 if strings.Contains(text,"files have been encrypted") &&
  (strings.Contains(text,"pay") || strings.Contains(text,"ransom") || strings.Contains(text,"bitcoin")) {
  *score+=70
  *reasons=append(*reasons,"Ransomware indicator: recovery-themed note with extortion language (not evidence of an active infection)")
 }
}

// RAR payload inspection is NOT implemented. A fake .rar containing exposed
// script text can be warned about; valid compressed RAR bytes are left alone.
func inspectMisnamedRAR(data []byte, score *int, reasons *[]string) {
 if len(data)<16 || bytes.HasPrefix(data,[]byte{'R','a','r','!',0x1a,0x07}) {return}
 var scriptScore int
 var scriptReasons []string
 inspectScript(data,&scriptScore,&scriptReasons)
 if scriptScore>=70 {
  *score+=52
  *reasons=append(*reasons,"Unrecognized RAR header with plaintext script indicators; archive extraction not available")
 }
}
