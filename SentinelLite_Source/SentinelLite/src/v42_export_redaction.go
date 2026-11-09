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

// Windows filesystem error strings frequently contain paths with spaces.
// For export redaction, preserve the failure category but no path fragments.
func v42SafeSkippedReason(reason string) string {
    lower:=strings.ToLower(reason)
    switch {
    case strings.Contains(lower,"reparse point")||strings.Contains(lower,"symbolic link"):
        return "symbolic link or reparse point not followed"
    case strings.Contains(lower,"quarantine directory"):
        return "SentinelGuard quarantine directory intentionally excluded"
    case strings.Contains(lower,"access is denied")||strings.Contains(lower,"permission denied"):
        if strings.Contains(lower,"directory listing failed"){return "directory listing denied"}
        return "file access denied"
    case strings.Contains(lower,"used by another process"):
        return "file is in use by another process"
    case strings.Contains(lower,"not a valid zip")||strings.Contains(lower,"zip archive could not be inspected"):
        return "ZIP archive could not be inspected"
    case strings.Contains(lower,"directory listing failed"):
        return "directory listing failed"
    case strings.Contains(lower,"file content could not be opened"):
        return "file content could not be opened"
    default:
        return "path was skipped or could not be inspected"
    }
}

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
    case "path","current","name","watchedfolders","executablepath","image","childprocessimages":
      if typed==""{return ""}
      if strings.ToLower(key)=="name" || strings.ToLower(key)=="image" || strings.ToLower(key)=="childprocessimages" {
          return tag(typed)+strings.ToLower(filepath.Ext(typed))
      }
      return tag(typed)
    case "sha256atscan":
      if typed==""{return ""}
      return "[digest redacted]"
    case "reason":
      lower:=strings.ToLower(typed)
      if strings.Contains(lower,"directory listing") ||
         strings.Contains(lower,"file content could not") ||
         strings.Contains(lower,"reparse point") ||
         strings.Contains(lower,"quarantine directory") ||
         strings.Contains(lower,"zip archive could not") {
        return v42SafeSkippedReason(typed)
      }
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
