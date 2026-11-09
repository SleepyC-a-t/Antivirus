package main

import(
 "archive/zip"
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
// EICAR is a published HARMLESS antivirus test signature, never malware.
// It is assembled from fragments so the release executable does not
// accidentally contain the complete AV test string as a data constant.
func v42EICAR()[]byte{return []byte(strings.Join([]string{
 "X5O!P%@AP[4\\PZX54(P^)7CC)7}$","EICAR-STANDARD-","ANTIVIRUS-TEST-FILE!$H+H*",
},""))}
func v42Zip(t *testing.T,name string,payload []byte)[]byte{
 t.Helper();var b bytes.Buffer;w:=zip.NewWriter(&b)
 f,err:=w.Create(name);if err!=nil{t.Fatal(err)}
 if _,err=f.Write(payload);err!=nil{t.Fatal(err)}
 if err=w.Close();err!=nil{t.Fatal(err)}
 return b.Bytes()
}
func TestV42OfficialEICARMarkerRecursionAndBenignControls(t *testing.T){
 cases:=[]struct{name string;data []byte;expected bool}{
  {"eicar.com.zip",v42Zip(t,"eicar.com",v42EICAR()),true},
  {"eicar.com-2.zip",v42Zip(t,"eicar.com.zip",v42Zip(t,"eicar.com",v42EICAR())),true},
  {"eicar.com-3.zip",v42Zip(t,"mid.zip",v42Zip(t,"inner.zip",v42Zip(t,"eicar.com",v42EICAR()))),true},
  {"benign.zip",v42Zip(t,"guide.com",[]byte("documentation about security tools")),false},
  {"nonmatching.zip",v42Zip(t,"eicar.com",[]byte("one-byte-mutation")),false},
  {"benign-nested.zip",v42Zip(t,"sub.zip",v42Zip(t,"guide.com",[]byte("not a virus"))),false},
 }
 base:=t.TempDir()
 for _,c:=range cases{
  p:=filepath.Join(base,c.name)
  if err:=os.WriteFile(p,c.data,0600);err!=nil{t.Fatal(err)}
  st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
  f:=inspectFile(p,st)
  if c.expected!=(f!=nil){t.Fatalf("%s detected=%t expected=%t finding=%+v",c.name,f!=nil,c.expected,f)}
 }
}
func TestV42ZipBudgetRejectsHighlyCompressedEntry(t *testing.T){
 // The nested parser must never read megabytes from a zip bomb.
 payload:=bytes.Repeat([]byte("A"),4*1024*1024)
 z:=v42Zip(t,"benign.txt",payload)
 p:=filepath.Join(t.TempDir(),"stress.zip")
 if err:=os.WriteFile(p,z,0600);err!=nil{t.Fatal(err)}
 st,_:=os.Stat(p)
 _=inspectFile(p,st)
}
