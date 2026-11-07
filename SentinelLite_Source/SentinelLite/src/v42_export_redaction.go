package main

import (
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "path/filepath"
 "regexp"
 "strings"
)

// Export-only redaction. The scanner, quarantine entries and stored events
// are not changed. Ephemeral salts avoid cross-report path correlations.
var v42PathString=regexp.MustCompile("(?i)(?:[A-Z]:\\\\|\\\\\\\\)[^ \\t\\r\\n\\\"'<>]+")
var v42UnixPathString=regexp.MustCompile("/(?:home|users)/[^ \\t\\r\\n\\\"'<>]+")
var v42WindowsUsername=regexp.MustCompile("(?i)(users\\\\)[^\\\\\\s]+")

func v42RedactReport(source any)(any,error){
 raw,err:=json.Marshal(source);if err!=nil{return nil,err}
 var obj any
 if err:=json.Unmarshal(raw,&obj);err!=nil{return nil,err}
 salt:=make([]byte,32);if _,err:=rand.Read(salt);err!=nil{return nil,err}
 tag:=func(raw string)string{
   h:=sha256.New();h.Write(salt);h.Write([]byte(raw))
   return "redacted-"+hex.EncodeToString(h.Sum(nil))[:16]
 }
 var scrub func(any,string)any
 scrub=func(value any,key string)any{
  switch typed:=value.(type){
  case map[string]any:
    out:=make(map[string]any,len(typed))
    for field,val:=range typed{out[field]=scrub(val,field)}
    return out
  case []any:
    out:=make([]any,len(typed))
    for i,val:=range typed{out[i]=scrub(val,key)}
    return out
  case string:
    switch strings.ToLower(key){
    case "path","current","name","watchedfolders":
      if typed==""{return ""}
      if strings.ToLower(key)=="name" {
          return tag(typed)+strings.ToLower(filepath.Ext(typed))
      }
      return tag(typed)
    }
    cleaned:=v42PathString.ReplaceAllStringFunc(typed,tag)
    cleaned=v42UnixPathString.ReplaceAllStringFunc(cleaned,tag)
    cleaned=v42WindowsUsername.ReplaceAllString(cleaned,"$1[user]")
    return cleaned
  default:return value
  }
 }
 redacted:=scrub(obj,"")
 if document,ok:=redacted.(map[string]any);ok{
     document["redacted"]=true
     document["redactionNotice"]="Absolute paths, filenames and obvious identifiers are masked for sharing. Timestamps, content hashes and other contextual data may remain; review before public distribution."
     return document,nil
 }
 return nil,fmt.Errorf("unsupported export shape")
}
