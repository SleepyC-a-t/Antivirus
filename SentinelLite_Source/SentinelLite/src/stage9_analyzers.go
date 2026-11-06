package main

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// SentinelGuard v3.0: bounded, advisory inspection of additional file formats.
// This never executes, imports, decompresses unknown formats or launches content.
// Multi-signal checks deliberately favour precision over spotting every
// suspicious word in source code and documentation.
var stage9XMLDeclaration = regexp.MustCompile(`(?is)^\s*<\?xml[^>]*\?>`)
var stage9CDisabled = regexp.MustCompile(`(?is)#if\s+0\b[\s\S]*?#endif`)
var stage9RansomMoney = regexp.MustCompile(`(?i)\b(?:pay|payment|send|transfer)\b[\s\S]{0,120}\b(?:btc|bitcoin|monero|xmr|wallet)\b|\b(?:btc|bitcoin|monero|xmr)\b[\s\S]{0,120}\b(?:pay|payment|send|transfer)\b`)
var stage9FileWrite = regexp.MustCompile(`(?i)\.(?:write_bytes|write_text)\s*\(|\bopen\s*\([^\r\n]{0,120}['"](?:wb|ab|w)['"]`)
var stage9JsRun = regexp.MustCompile(`(?i)\.\s*run\s*\(`)
var stage9PSHidden = regexp.MustCompile(`(?i)(?:-w(?:indowstyle)?\s+hidden|-windowstyle\s+hidden)`)

type stage9Task struct {
	XMLName xml.Name `xml:"Task"`
	Triggers struct {
		Logon []struct{} `xml:"LogonTrigger"`
		Boot []struct{} `xml:"BootTrigger"`
	} `xml:"Triggers"`
	Settings struct {
		Hidden string `xml:"Hidden"`
	} `xml:"Settings"`
	Principals struct {
		Principal []struct{
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		Exec []struct{
			Command string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func stage9HasUserWritableTarget(target string) bool {
	target = strings.ToLower(strings.ReplaceAll(target, "/", "\\"))
	return strings.Contains(target, "\\users\\public\\") ||
		strings.Contains(target, "\\appdata\\") ||
		strings.Contains(target, "\\temp\\") ||
		strings.Contains(target, "%appdata%") ||
		strings.Contains(target, "%temp%")
}

func inspectStage9Content(name, ext string, data []byte, score *int, reasons *[]string) {
	if len(data)==0 {return}
	// Avoid processing whole Office bundles or other massive files.
	if len(data)>2*1024*1024{return}
	src:=decodeScriptText(data)
	lower:=strings.ToLower(src)
	add:=func(points int,reason string){*score+=points;*reasons=append(*reasons,reason)}

	switch ext {
	case ".txt":
		// A threat note is not evidence of a running ransomware process.
		// Filename, coercive language and cryptocurrency demand must agree.
		file:=strings.ToLower(name)
		if !(strings.Contains(file,"restore") || strings.Contains(file,"recover") ||
			strings.Contains(file,"decrypt") || strings.Contains(file,"readme")) {return}
		for _,reason:=range *reasons {if strings.HasPrefix(reason,"Ransomware indicator:"){return}}
		if !(strings.Contains(lower,"your documents have been locked") ||
			strings.Contains(lower,"files have been locked") ||
			strings.Contains(lower,"your files have been encrypted") ||
			strings.Contains(lower,"files are encrypted")) {return}
		if stage9RansomMoney.MatchString(lower) &&
			(strings.Contains(lower,"recover") || strings.Contains(lower,"restore") || strings.Contains(lower,"decrypt")) {
			add(67,"Ransomware indicator: recovery-themed extortion note (could be a simulation or inactive text)")
		}
	case ".xml":
		if len(src)>512*1024 || !strings.Contains(lower,"<task") ||
			!strings.Contains(lower,"<exec>") || !strings.Contains(lower,"<command>") {return}
		normalized:=strings.TrimSpace(stage9XMLDeclaration.ReplaceAllString(src,""))
		var task stage9Task
		if xml.Unmarshal([]byte(normalized),&task)!=nil || task.XMLName.Local!="Task" {return}
		high:=false
		for _,principal:=range task.Principals.Principal {
			if strings.EqualFold(strings.TrimSpace(principal.RunLevel),"HighestAvailable") {high=true}
		}
		if !high || !strings.EqualFold(strings.TrimSpace(task.Settings.Hidden),"true") ||
			(len(task.Triggers.Logon)==0 && len(task.Triggers.Boot)==0) {return}
		for _,action:=range task.Actions.Exec {
			target:=strings.TrimSpace(action.Command+" "+action.Arguments)
			if stage9HasUserWritableTarget(target) &&
				(strings.Contains(strings.ToLower(target),".exe") ||
				 strings.Contains(strings.ToLower(target),"powershell")) {
				add(72,"Persistence: hidden elevated logon/boot task executes a file from a user-writable location")
				break
			}
		}
	case ".reg":
		if len(src)>512*1024 || !strings.Contains(lower,"windows registry editor version") {return}
		if !(strings.Contains(lower,"\\currentversion\\run") ||
			strings.Contains(lower,"\\winlogon")) {return}
		// Importable registry files only. A .reg.txt document must not count.
		if stage9HasUserWritableTarget(lower) &&
			(strings.Contains(lower,".exe") || strings.Contains(lower,"powershell")) {
			add(67,"Persistence: registry import defines startup execution from a user-writable location")
		}
	case ".json":
		if len(src)>256*1024 || !strings.Contains(lower,"\"targets\"") ||
			!strings.Contains(lower,"\"exfil\"") {return}
		var obj struct {
			Enabled bool `json:"enabled"`
			Targets []string `json:"targets"`
			Exfil struct {
				URL string `json:"url"`
				Method string `json:"method"`
			} `json:"exfil"`
		}
		if json.Unmarshal(data,&obj)!=nil || !obj.Enabled {return}
		credentials:=0
		for _,target:=range obj.Targets {
			t:=strings.ToLower(target)
			if strings.Contains(t,"login data") || strings.Contains(t,"cookies") ||
				strings.Contains(t,"wallet") || strings.Contains(t,"password") {credentials++}
		}
		if credentials>=2 && (strings.HasPrefix(strings.ToLower(obj.Exfil.URL),"https://") ||
			strings.HasPrefix(strings.ToLower(obj.Exfil.URL),"http://")) &&
			strings.EqualFold(obj.Exfil.Method,"POST") {
			add(68,"Credential exfiltration configuration: enabled credential targets and remote POST destination")
		}
	case ".py":
		if !strings.Contains(lower,"socket") && !strings.Contains(lower,"encrypt") &&
			!strings.Contains(lower,"login data") && !strings.Contains(lower,"gethost") {return}
		code:=strings.ToLower(codeOnlyForSignals(src))
		if (strings.Contains(code,"os.walk(") || strings.Contains(code,".rglob(") ||
			strings.Contains(code,"glob.glob(")) &&
			stage9FileWrite.MatchString(lower) &&
			(strings.Contains(code,".encrypt(") || strings.Contains(code,"fernet(")) {
			add(86,"Ransomware-like Python behavior: enumerates local files, encrypts and writes results")
		}
		if strings.Contains(code,"sqlite3.connect(") &&
			(strings.Contains(lower,"login data") || strings.Contains(lower,"cookies")) &&
			strings.Contains(code,".fetchall(") &&
			(strings.Contains(code,"requests.post(") || strings.Contains(code,"urlopen(")) {
			add(88,"Credential access and exfiltration: browser database read combined with outbound transfer")
		}
		if strings.Contains(code,"socket.socket(") && strings.Contains(code,".connect(") &&
			strings.Contains(code,".recv(") &&
			(strings.Contains(code,"subprocess.run(") || strings.Contains(code,"subprocess.popen(")) &&
			strings.Contains(code,".send(") {
			add(90,"Remote control: socket command loop invokes subprocess and sends results")
		}
		if (strings.Contains(code,"socket.gethostbyname(") || strings.Contains(code,"socket.getaddrinfo(")) &&
			strings.Contains(code,".hex(") && strings.Contains(code,"for ") {
			add(52,"Network anomaly: programmatically resolves encoded data-bearing DNS labels")
		}
	case ".js", ".jse":
		// A string containing a shell name is common in browser code; a
		// Windows Script Host object plus an actual Run invocation is rarer.
		if !strings.Contains(lower,"wscript.shell") || !strings.Contains(lower,"activexobject") {return}
		code:=strings.ToLower(codeOnlyForSignals(src))
		if strings.Contains(code,"activexobject(") && stage9JsRun.MatchString(code) &&
			(strings.Contains(lower,"powershell") || strings.Contains(lower,"cmd.exe") ||
			strings.Contains(lower,"mshta")) {
			add(78,"Script execution: Windows Script Host launches an interpreter command")
		}
	case ".c", ".cpp":
		if !(strings.Contains(lower,"virtualallocex") && strings.Contains(lower,"createremotethread")) {return}
		// #if 0 blocks in published examples are disabled code, not active.
		code:=strings.ToLower(codeOnlyForSignals(stage9CDisabled.ReplaceAllString(src,"")))
		if strings.Contains(code,"openprocess(") && strings.Contains(code,"virtualallocex(") &&
			strings.Contains(code,"writeprocessmemory(") && strings.Contains(code,"createremotethread(") {
			add(66,"Source review: process memory modification and remote-thread API chain (may be legitimate tooling)")
		}
	case ".bas":
		if !strings.Contains(lower,"autoopen") && !strings.Contains(lower,"document_open") {return}
		code:=strings.ToLower(codeOnlyForSignals(src))
		if (strings.Contains(code,"sub autoopen(") || strings.Contains(code,"sub document_open(")) &&
			(strings.Contains(code,"shell(") || strings.Contains(code,".run(")) &&
			(strings.Contains(lower,"powershell") || strings.Contains(lower,"wscript.shell")) {
			add(76,"Office macro source: automatic-open procedure launches an interpreter")
		}
	case ".ps1", ".psm1":
		if !strings.Contains(lower,"invoke-webrequest") && !strings.Contains(lower,"invoke-restmethod") {return}
		code:=strings.ToLower(codeOnlyForSignals(src))
		if (strings.Contains(code,"invoke-webrequest") || strings.Contains(code,"invoke-restmethod")) &&
			strings.Contains(code,"start-process") && stage9PSHidden.MatchString(code) {
			add(73,"Script execution: hidden PowerShell process launches remotely retrieved content")
		}
	}
}
