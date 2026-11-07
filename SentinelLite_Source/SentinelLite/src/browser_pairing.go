package main

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

type BrowserPairConfig struct {
    Port int `json:"port"`
    Secret string `json:"secret"`
}
const pairSecretBytes=32

func generateBrowserPairConfig() (BrowserPairConfig,error){
    buffer:=make([]byte,pairSecretBytes+2)
    if _,err:=rand.Read(buffer);err!=nil{return BrowserPairConfig{},err}
    port:=40000+int(binary.LittleEndian.Uint16(buffer[pairSecretBytes:])%20000)
    return BrowserPairConfig{Port:port,Secret:base64.RawURLEncoding.EncodeToString(buffer[:pairSecretBytes])},nil
}
func pairingValid(c BrowserPairConfig)bool {
    b,err:=base64.RawURLEncoding.DecodeString(c.Secret)
    return err==nil&&len(b)==pairSecretBytes&&c.Port>=40000&&c.Port<60000
}
func pairingFilePath() string{
    root:=os.Getenv("LOCALAPPDATA")
    if root=="" {root,_=os.UserConfigDir()}
    return filepath.Join(root,"SentinelLite","browser_pairing.dpapi")
}
func saveBrowserPairing(path string,config BrowserPairConfig)error{
    if !pairingValid(config){return errors.New("invalid browser pairing configuration")}
    data,err:=json.Marshal(config);if err!=nil{return err}
    encrypted,err:=encryptLocalPairing(data);if err!=nil{return err}
    if err=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
    file,err:=os.CreateTemp(filepath.Dir(path),".pairing-*");if err!=nil{return err}
    defer os.Remove(file.Name())
    if err=file.Chmod(0600);err!=nil{file.Close();return err}
    if _,err=file.Write(encrypted);err!=nil{file.Close();return err}
    if err=file.Sync();err!=nil{file.Close();return err}
    if err=file.Close();err!=nil{return err}
    if err=os.Rename(file.Name(),path);err!=nil{return err}
    return nil
}
func loadOrCreateBrowserPairing(path string)(BrowserPairConfig,error){
    if path=="" {path=pairingFilePath()}
    data,err:=os.ReadFile(path)
    if err==nil {
        plaintext,err:=decryptLocalPairing(data)
        if err!=nil{return BrowserPairConfig{},fmt.Errorf("cannot decrypt saved browser pairing: %w",err)}
        var old BrowserPairConfig
        if err=json.Unmarshal(plaintext,&old);err!=nil{return BrowserPairConfig{},err}
        if !pairingValid(old){return BrowserPairConfig{},errors.New("invalid saved pairing; re-pair required")}
        return old,nil
    }
    if !os.IsNotExist(err){return BrowserPairConfig{},err}
    fresh,err:=generateBrowserPairConfig();if err!=nil{return BrowserPairConfig{},err}
    if err=saveBrowserPairing(path,fresh);err!=nil{return BrowserPairConfig{},err}
    return fresh,nil
}
func rotateBrowserPairing(path string,old BrowserPairConfig)(BrowserPairConfig,error){
    if !pairingValid(old){return BrowserPairConfig{},errors.New("invalid existing identity")}
    next,err:=generateBrowserPairConfig();if err!=nil{return BrowserPairConfig{},err}
    next.Port=old.Port // stable bound listener; revoke only the read-only key
    if err=saveBrowserPairing(path,next);err!=nil{return BrowserPairConfig{},err}
    return next,nil
}
func signBrowserState(secret,nonce string,enabled bool)string{
    h:=hmac.New(sha256.New,[]byte(secret))
    state:="false";if enabled{state="true"}
    _,_=h.Write([]byte(nonce+"|"+state+"|SentinelGuard 4.1"))
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
