package main

import (
    "encoding/base64"
    "testing"
)

func TestBrowserPairingHMACAndRandomness(t *testing.T){
    a,err:=generateBrowserPairConfig();if err!=nil{t.Fatal(err)}
    b,err:=generateBrowserPairConfig();if err!=nil{t.Fatal(err)}
    if !pairingValid(a)||!pairingValid(b)||a.Secret==b.Secret{t.Fatal("invalid or repeated pairing identity")}
    nonce:="abcdEFGH0123456789_abcdEFGH"
    off:=signBrowserState(a.Secret,nonce,false)
    on:=signBrowserState(a.Secret,nonce,true)
    if on==off || on==signBrowserState(b.Secret,nonce,true) {
        t.Fatal("pairing signature not bound to key and enabled state")
    }
    encoded,err:=base64.RawURLEncoding.DecodeString(on)
    if err!=nil||len(encoded)!=32 {t.Fatal("invalid HMAC result")}
}
