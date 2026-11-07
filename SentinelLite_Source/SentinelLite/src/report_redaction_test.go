package main
import(
 "encoding/json"
 "strings"
 "testing"
)
func TestV42RedactedExportProtectsPersonalIdentifiersAndPreservesDecisions(t *testing.T){
 source:=map[string]any{
  "version":"4.2",
  "status":map[string]any{"current":`C:\Users\ExampleUser\Documents\private-work`,"files":248},
  "findings":[]any{map[string]any{"path":`C:\Users\ExampleUser\Downloads\tax-return.exe`,"name":"tax-return.exe","score":115,"reasons":[]string{"Hidden path C:\\Users\\ExampleUser\\Documents"}}},
  "liveProtection":map[string]any{"watchedFolders":[]string{`C:\Users\ExampleUser\Downloads`},"launchEvents":[]any{
      map[string]any{"path":`C:\Users\ExampleUser\Downloads\tax-return.exe`,"sha256":"0123456789abcdef","action":"launch-denied","at":"2026-11-07T17:00:00Z"},
  }},
 }
 out,err:=redactExport(source);if err!=nil{t.Fatal(err)}
 b,_:=json.Marshal(out)
 text:=string(b)
 for _,secret:=range []string{"ExampleUser","tax-return.exe","0123456789abcdef","private-work","Hidden path"} {
   if strings.Contains(text,secret){t.Fatalf("redacted report leaked %q: %s",secret,text)}
 }
 for _,must:=range []string{"launch-denied","115","248","2026-11-07T17:00:00Z","redacted"}{
   if !strings.Contains(text,must){t.Fatalf("redacted report lost %q",must)}
 }
 full,_:=json.Marshal(source)
 if !strings.Contains(string(full),"ExampleUser"){t.Fatal("redaction must not mutate the original full report")}
}
