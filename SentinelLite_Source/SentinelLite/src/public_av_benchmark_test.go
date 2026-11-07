package main

import (
    "archive/zip"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
)

const canonicalEicarSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fea2c4538aabf651fd0f"

// SOURCE: https://www.eicar.org/download-anti-malware-testfile/
//
// These are INERT, universally published antivirus testing bytes.
// They are not live malware. The complete EICAR signature is assembled
// from strings to avoid embedding a complete test signature in the compiled
// executable. This suite runs in an isolated Linux GitHub Actions runner.
// Windows primary antivirus may quarantine the fixtures independently.
func publicEICARBytes() []byte {
    return []byte(strings.Join([]string{
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!$H+H*",
    }, ""))
}
func publicZIP(t *testing.T, name string, data []byte) []byte {
    t.Helper()
    var b bytes.Buffer
    z := zip.NewWriter(&b)
    w, err := z.Create(name)
    if err != nil {t.Fatal(err)}
    if _, err = w.Write(data); err != nil {t.Fatal(err)}
    if err = z.Close(); err != nil {t.Fatal(err)}
    return b.Bytes()
}

func TestPublicEICARFourOfficialFormatsAndNegativeControls(t *testing.T) {
    if runtime.GOOS=="windows" {
        t.Skip("Create the safe EICAR test files on isolated Linux CI; normal Windows AV may quarantine them independently")
    }
    payload:=publicEICARBytes()
    digest:=sha256.Sum256(payload)
    if len(payload)!=68||hex.EncodeToString(digest[:])!=canonicalEicarSHA256 {
        t.Fatal("Public EICAR fixture differs from the original published 68-byte standard")
    }
    once:=publicZIP(t,"eicar.com",payload)
    twice:=publicZIP(t,"eicar.com.zip",once)
    // The ZIPs have the same structure as EICAR's published forms, but
    // independently generated ZIP metadata; they are NOT byte-identical
    // to the official downloadable 184-/308-byte archives.
    samples:=[]struct{
        name string
        content []byte
        expectedIndicator bool
        source string
    }{
        {"eicar.com",payload,true,"Official EICAR 68-byte payload"},
        {"eicar.com.txt",payload,true,"Official EICAR 68-byte payload with .txt name"},
        {"eicar.com.zip",once,true,"Reconstructed one-level ZIP containing the canonical EICAR file"},
        {"eicar.com-2.zip",twice,true,"Reconstructed two-level ZIP containing the canonical EICAR file"},
        {"eicar-trailing-newline.com",append(append([]byte{},payload...),'\n'),true,"Valid EICAR optional trailing newline"},
        {"modified-com.txt",append([]byte{},payload...),false,"One-byte negative control (mutated EICAR)"},
        {"eicar-quoted-guide.txt",[]byte("This is a documentation quote: "+string(payload)+" and nothing is being executed."),false,"Benign prose quotation (not standalone EICAR)"},
        {"clean-readme.txt",[]byte("Harmless readme. No executable content."),false,"Benign plain-text control"},
    }
    // Make the negative 'modified' control genuinely different.
    samples[5].content[2]^=1
    dir:=t.TempDir()
    tp,fn,fp,tn:=0,0,0,0
    for _,s:=range samples{
        path:=filepath.Join(dir,s.name)
        if err:=os.WriteFile(path,s.content,0600);err!=nil{t.Fatal(err)}
        st,err:=os.Lstat(path);if err!=nil{t.Fatal(err)}
        finding:=inspectFileProtected(path,st,nil)
        flagged:=finding!=nil
        if s.expectedIndicator {
            if flagged {tp++} else {fn++}
        } else if flagged {fp++}else{tn++}
        score,reason:=0,""
        if finding!=nil {score=finding.Score;reason=strings.Join(finding.Reasons," | ")}
        hash:=sha256.Sum256(s.content)
        t.Logf("PUBLIC_EICAR_CASE name=%q expected=%t detected=%t score=%d length=%d sha256=%s reason=%q origin=%q",s.name,s.expectedIndicator,flagged,score,len(s.content),hex.EncodeToString(hash[:]),reason,s.source)
    }
    t.Logf("PUBLIC_EICAR_TOTAL TP=%d FN=%d FP=%d TN=%d canonicalSHA256=%s",tp,fn,fp,tn,canonicalEicarSHA256)
}

func TestPublicAMTSOSimulatedPUAReadOnly(t *testing.T){
    // SOURCE: https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/
    // Download only in temporary isolated CI; do not execute this EXE.
    path:=os.Getenv("SENTINELGUARD_AMTSO_PUA_FILE")
    if path=="" {t.Skip("Official AMTSO PUA test binary unavailable; no test result is claimed")}
    stat,err:=os.Stat(path)
    if err!=nil{t.Skipf("AMTSO test binary could not be read: %v",err)}
    if !stat.Mode().IsRegular()||stat.Size()<64||stat.Size()>5*1024*1024{
        t.Skipf("AMTSO test file is not an eligible bounded binary, size=%d",stat.Size())
    }
    f,err:=os.Open(path);if err!=nil{t.Fatal(err)}
    defer f.Close()
    h:=sha256.New()
    if _,err:=io.Copy(h,io.LimitReader(f,5*1024*1024+1));err!=nil{t.Fatal(err)}
    sha:=hex.EncodeToString(h.Sum(nil))
    finding:=inspectFileProtected(path,stat,nil)
    score,reason:=0,""
    if finding!=nil{score=finding.Score;reason=strings.Join(finding.Reasons," | ")}
    t.Logf("PUBLIC_AMTSO_PUA_FILE detected=%t score=%d size=%d sha256=%s reasons=%q source=%q",finding!=nil,score,stat.Size(),sha,"https://amtso.eicar.org/PotentiallyUnwanted.exe")
    t.Log("AMTSO PUA is a published harmless PUA simulation. A miss does not imply a known malware family was missed.")
}
