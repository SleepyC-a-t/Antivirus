package main

import (
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "strings"
)
// redactExport makes a pseudonymous, per-export view of full JSON evidence.
// The random HMAC key is NOT embedded in the report. This makes repeated
// names/paths linkable within one report but not across separate exports.
func redactExport(raw any)(any,error){
    secret:=make([]byte,32)
    if _,err:=rand.Read(secret);err!=nil{return nil,err}
    encoded,err:=json.Marshal(raw)
    if err!=nil{return nil,err}
    var data any
    if err:=json.Unmarshal(encoded,&data);err!=nil{return nil,err}
    aliases:=map[string]string{}
    var rewrite func(any,string)any
    rewrite=func(value any,key string)any {
        lower:=strings.ToLower(key)
        switch lower {
        case "reasons","reason","lasterror","error":
            return "[free-form details withheld in redacted export]"
        case "path","name","current","watchedfolders","filename","sha256","reviewsha256":
            if text,ok:=value.(string);ok{
                if text==""{return ""}
                if old,exists:=aliases[text];exists{return old}
                mac:=hmac.New(sha256.New,secret)
                _,_=mac.Write([]byte(text))
                alias:="private-"+hex.EncodeToString(mac.Sum(nil)[:10])
                aliases[text]=alias
                return alias
            }
            if values,ok:=value.([]any);ok {
                out:=make([]any,0,len(values))
                for _,entry:=range values{out=append(out,rewrite(entry,"path"))}
                return out
            }
        }
        switch v:=value.(type){
        case []any:
            out:=make([]any,0,len(v))
            for _,entry:=range v{out=append(out,rewrite(entry,""))}
            return out
        case map[string]any:
            for k,entry:=range v {v[k]=rewrite(entry,k)}
            return v
        default:
            return value
        }
    }
    mapped:=rewrite(data,"")
    doc,ok:=mapped.(map[string]any)
    if !ok{return nil,errors.New("unexpected report data shape")}
    doc["redacted"]=true
    doc["redactionNotice"]="Filenames, paths and file hashes pseudonymized with an export-local random key. Free-form reasons/errors omitted. Scores, timestamps and operational metadata retained; review before sharing."
    return doc,nil
}
