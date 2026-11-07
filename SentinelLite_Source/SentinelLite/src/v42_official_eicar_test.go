package main

import(
 "archive/zip"
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "testing"
)
func TestV42OfficialPublishedEicarZIPsReadOnly(t *testing.T){
 folder:=os.Getenv("SENTINELGUARD_EICAR_OFFICIAL_DIR")
 if folder==""{t.Skip("official ZIP downloads not provided; reconstructed ZIP regression tested separately")}
 originals:=[]struct{name string;expected int}{
  {"eicar_com.zip",184},
  {"eicarcom2.zip",308},
 }
 dir:=t.TempDir()
 for _,s:=range originals {
  data,err:=os.ReadFile(filepath.Join(folder,s.name))
  if err!=nil{t.Skipf("official %s absent: %v",s.name,err)}
  if len(data)!=s.expected {t.Fatalf("official EICAR %s is %d bytes, expected published size %d",s.name,len(data),s.expected)}
  // Confirm ZIP structure and harmless exact canonical signature inside,
  // never run or open any archive member through the shell.
  zr,err:=zip.NewReader(bytes.NewReader(data),int64(len(data)))
  if err!=nil{t.Fatal(err)}
  digest:=sha256.Sum256(data)
  p:=filepath.Join(dir,s.name)
  if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
  info,_:=os.Stat(p)
  f:=inspectFileProtected(p,info,nil)
  score:=0
  if f!=nil{score=f.Score}
  t.Logf("V42_OFFICIAL_EICAR_ARCHIVE file=%s found=%t score=%d sha256=%s entries=%d",
     s.name,f!=nil,score,hex.EncodeToString(digest[:]),len(zr.File))
  if f==nil{t.Fatalf("official harmless EICAR archive %s was not detected",s.name)}
 }
}
