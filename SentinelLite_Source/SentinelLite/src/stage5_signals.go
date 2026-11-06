package main

import (
 "bytes"
 "os"
 "regexp"
 "strings"
)

// Remove nonexecuting strings and comments from heuristic matching. This is a
// conservative lexical filter, not a full language parser. Strings later
// passed to eval/IEX still require further investigation.
func codeOnlyForSignals(src string) string {
 var out strings.Builder
 out.Grow(len(src))
 block := byte(0) // 1 = PowerShell <# #>, 2 = JS /* */
 quote := byte(0)
 atLineStart := true
 for i := 0; i < len(src); {
  c := src[i]
  if c == '\n' || c == '\r' {
   out.WriteByte('\n')
   if c == '\r' && i+1 < len(src) && src[i+1] == '\n' { i++ }
   i++
   atLineStart = true
   continue
  }
  if block != 0 {
   if block == 1 && i+1 < len(src) && src[i] == '#' && src[i+1] == '>' { block = 0; i += 2; continue }
   if block == 2 && i+1 < len(src) && src[i] == '*' && src[i+1] == '/' { block = 0; i += 2; continue }
   i++
   continue
  }
  if quote != 0 {
   if c == '\\' && i+1 < len(src) { i += 2; continue }
   if c == '`' && i+1 < len(src) { i += 2; continue }
   if c == quote {
    if quote == '\'' && i+1 < len(src) && src[i+1] == '\'' { i += 2; continue }
    quote = 0
   }
   i++
   continue
  }
  if atLineStart {
   if c == ' ' || c == '\t' { out.WriteByte(c); i++; continue }
   rest := strings.ToLower(src[i:min(i+12,len(src))])
   if strings.HasPrefix(rest, "#") || strings.HasPrefix(rest, "//") || strings.HasPrefix(rest, "::") ||
    strings.HasPrefix(rest, "rem ") || strings.HasPrefix(rest, "@rem ") ||
    strings.HasPrefix(rest, "echo ") || strings.HasPrefix(rest, "@echo ") {
    for i < len(src) && src[i] != '\r' && src[i] != '\n' { i++ }
    continue
   }
   atLineStart = false
  }
  if i+1 < len(src) && c == '<' && src[i+1] == '#' { block = 1; i+=2; continue }
  if i+1 < len(src) && c == '/' && src[i+1] == '*' { block = 2; i+=2; continue }
  if c == '\'' || c == '"' { quote = c; i++; continue }
  out.WriteByte(c)
  i++
 }
 return out.String()
}

var htaRemotePattern = regexp.MustCompile(`(?i)\bmshta(?:\.exe)?\s+https?://[^\s]+`)
var jsRemoteEvalPattern = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:await\s+)?fetch\s*\(`)

func inspectStage5Patterns(buf []byte, ext string, score *int, reasons *[]string) {
 raw := strings.ToLower(decodeScriptText(buf))
 if !strings.Contains(raw,"mshta") && !(strings.Contains(raw,"eval") && strings.Contains(raw,"fetch")) { return }
 lower := strings.ToLower(codeOnlyForSignals(raw))
 if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".hta") && htaRemotePattern.MatchString(lower) {
  *score += 70
  *reasons = append(*reasons, "Uses mshta to open a remote script/document (manual review recommended)")
 }
 if (ext == ".js" || ext == ".jse" || ext == ".hta") && jsRemoteEvalPattern.MatchString(lower) {
  *score += 85
  *reasons = append(*reasons, "JavaScript evaluates content retrieved via fetch()")
 }
}

var magic7z = []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}

// This identifies misnamed plaintext, NOT malware inside valid compressed 7z.
func inspectMisnamed7z(buf []byte, score *int, reasons *[]string) {
 if bytes.HasPrefix(buf, magic7z) { return }
 var s int
 var r []string
 inspectScript(buf, &s, &r)
 if s >= 70 {
  *score += 55
  *reasons = append(*reasons, "Invalid 7z signature with suspicious plaintext (not an extracted archive)")
 }
}

func hasPEFileSignature(path string) bool {
 file,err:=os.Open(path)
 if err!=nil{return false}
 defer file.Close()
 var header [1024]byte
 n,_:=file.Read(header[:])
 return isPEHeader(header[:n])
}
