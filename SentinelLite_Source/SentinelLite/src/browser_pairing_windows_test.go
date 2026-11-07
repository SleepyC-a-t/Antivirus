//go:build windows

package main

import (
    "path/filepath"
    "testing"
)

func TestWindowsDPAPIBrowserPairingSurvivesRestartAndRevokes(t *testing.T){
    p:=filepath.Join(t.TempDir(),"pairing.dpapi")
    one,err:=loadOrCreateBrowserPairing(p);if err!=nil{t.Fatal(err)}
    two,err:=loadOrCreateBrowserPairing(p);if err!=nil{t.Fatal(err)}
    if one!=two {t.Fatal("pairing was not persisted across app starts")}
    rotated,err:=rotateBrowserPairing(p,one);if err!=nil{t.Fatal(err)}
    if rotated.Port!=one.Port||rotated.Secret==one.Secret{t.Fatal("revocation did not rotate key")}
    reload,err:=loadOrCreateBrowserPairing(p);if err!=nil{t.Fatal(err)}
    if reload!=rotated{t.Fatal("restarted app did not reuse revoked replacement key")}
}
