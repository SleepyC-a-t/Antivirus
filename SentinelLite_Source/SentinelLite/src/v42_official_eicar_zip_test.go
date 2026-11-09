package main
import(
 "crypto/sha256"
 "encoding/hex"
 "os"
 "testing"
)
// Official EICAR ZIPs are harmless AV feature-test data. They are NEVER
// executed. Exact SHA-256 checks prevent substitutions by mirrors.
// These expected detections are REGRESSION LOCKS, not real malware scores.
func TestV42OfficialVendorEICARZipsHashChecked(t *testing.T){
 samples:=[]struct{env,hash string;size int64}{
  {"SENTINELGUARD_OFFICIAL_EICAR_ZIP","2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad",184},
  {"SENTINELGUARD_OFFICIAL_EICAR_ZIP2","e1105070ba828007508566e28a2b8d4c65d192e9eaf3b7868382b7cae747b397",308},
 }
 for _,item:=range samples{
   p:=os.Getenv(item.env)
   if p==""{t.Skipf("official EICAR ZIP not fetched for %s; no claim of official-byte coverage",item.env)}
   data,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
   h:=sha256.Sum256(data)
   if int64(len(data))!=item.size||hex.EncodeToString(h[:])!=item.hash{
      t.Fatalf("official EICAR ZIP integrity failure for %s; byte mismatch",item.env)
   }
   st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
   f:=inspectFileProtected(p,st,nil)
   t.Logf("OFFICIAL_EICAR_ZIP name=%s sha256=%s size=%d detected=%t",item.env,item.hash,item.size,f!=nil)
   if f==nil{t.Errorf("official harmless nested EICAR test marker missed for %s",item.env)}
 }
}
