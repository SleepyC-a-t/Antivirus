package main

import(
 "archive/zip"
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func v42Eicar()[]byte{return []byte(strings.Join([]string{"X5O!P%@AP[4\\PZX54(P^)7CC)7}$","EICAR-STANDARD-","ANTIVIRUS-TEST-FILE!$H+H*"},""))}
func v42Zip(t *testing.T,name string,data []byte)[]byte{
 t.Helper()
 var b bytes.Buffer
 z:=zip.NewWriter(&b)
 w,e:=z.Create(name);if e!=nil{t.Fatal(e)}
 if _,e=w.Write(data);e!=nil{t.Fatal(e)}
 if e=z.Close();e!=nil{t.Fatal(e)}
 return b.Bytes()
}
func TestV42EicarZIPAndNestedZIPRegression(t *testing.T){
 e:=v42Eicar()
 sha:=sha256.Sum256(e)
 if len(e)!=68 || hex.EncodeToString(sha[:])!="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {t.Fatal("EICAR reference bytes changed")}
 once:=v42Zip(t,"eicar.com",e)
 twice:=v42Zip(t,"eicar.com.zip",once)
 cases:=[]struct{name string;data []byte;want bool}{
  {"standalone.com",e,true},
  {"eicar_com.zip",once,true},
  {"eicarcom2.zip",twice,true},
  {"quote.zip",v42Zip(t,"README.txt",[]byte("An EICAR string in docs: "+string(e)+" is not a separate test sample")),false},
  {"clean.zip",v42Zip(t,"eicar.com",[]byte("this isn't the EICAR test")),false},
 }
 dir:=t.TempDir()
 for _,c:=range cases{
    p:=filepath.Join(dir,c.name)
    if err:=os.WriteFile(p,c.data,0600);err!=nil{t.Fatal(err)}
    st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
    f:=inspectFileProtected(p,st,nil)
    score:=0
    if f!=nil{score=f.Score}
    t.Logf("V42_EICAR name=%q match=%t expected=%t score=%d",c.name,f!=nil,c.want,score)
    if (f!=nil)!=c.want{t.Fatalf("EICAR regression for %s: got %t expected %t",c.name,f!=nil,c.want)}
 }
}
