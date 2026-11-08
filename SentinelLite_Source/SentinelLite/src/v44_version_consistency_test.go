package main

import (
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "testing"
)

// The Go constant is authoritative; bundled HTML is a 4.2 fallback until
// the local API supplies product.edition. Extension HMAC framing is a
// wire-format protocol; its edition must match the same constant.
func TestSecurityReleaseEditionVersionParity(t *testing.T) {
    if appVersion!="4.2" || appEdition!="SentinelGuard "+appVersion {
        t.Fatalf("unintended product version: %q %q",appVersion,appEdition)
    }
    stale:=regexp.MustCompile(`(?i)sentinelguard 4\.\d+`)
    entries,err:=os.ReadDir(".");if err!=nil{t.Fatal(err)}
    for _,e:=range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(),".go") || strings.HasSuffix(e.Name(),"_test.go") {continue}
        b,err:=os.ReadFile(e.Name());if err!=nil{t.Fatal(err)}
        for _,match:=range stale.FindAllString(string(b),-1) {
            if !strings.EqualFold(match,appEdition){
                t.Errorf("%s: stale edition %q (expected %q)",e.Name(),match,appEdition)
            }
        }
    }
    html,err:=os.ReadFile("ui.html");if err!=nil{t.Fatal(err)}
    for _,match:=range stale.FindAllString(string(html),-1) {
        if !strings.EqualFold(match,appEdition){t.Errorf("UI stale edition %q",match)}
    }
    src:=string(html)
    if !strings.Contains(src,"v4.2</span>") || !strings.Contains(src,"SENTINELGUARD 4.2") ||
        !strings.Contains(src,"securityHoldBanner") ||
        !strings.Contains(src,"appEditionHeader"){
        t.Fatal("UI lacks matching edition or visible security hold")
    }
    root:=filepath.Join("..","..","..","Active_Edition")
    for _,path:=range []string{
        filepath.Join(root,"browser-extension","background.js"),
        filepath.Join(root,"browser-extension-firefox","background.js"),
    }{
        b,err:=os.ReadFile(path);if err!=nil{t.Fatalf("companion source %s: %v",path,err)}
        s:=string(b)
        if !strings.Contains(s,`payload.edition!=="`+appEdition+`"`) ||
            !strings.Contains(s,`"SG`+appVersion+`|"`){
            t.Errorf("browser HMAC/edition protocol is not synchronized with %s",appEdition)
        }
    }
}
