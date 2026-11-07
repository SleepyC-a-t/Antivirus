package main

import(
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

type independentHoldoutManifest struct {
    Version int `json:"version"`
    Source string `json:"source"`
    LabelProvenance string `json:"labelProvenance"`
    Samples []struct {
        Path string `json:"path"`
        Label string `json:"label"`
        SHA256 string `json:"sha256"`
    } `json:"samples"`
}
type independentResult struct {
    Path string `json:"path"`
    Label string `json:"label"`
    Detected bool `json:"detected"`
    Score int `json:"score"`
    Reasons []string `json:"reasons,omitempty"`
    Error string `json:"error,omitempty"`
}
type independentSummary struct{
    Timestamp time.Time `json:"timestamp"`
    Source string `json:"source"`
    LabelProvenance string `json:"labelProvenance"`
    TP int `json:"tp"`
    FN int `json:"fn"`
    FP int `json:"fp"`
    TN int `json:"tn"`
    Uninspected int `json:"uninspected"`
    Results []independentResult `json:"results"`
    Note string `json:"note"`
}
func evaluateIndependentHoldout(manifestPath string)(independentSummary,error) {
    manifestStat,err:=os.Stat(manifestPath)
    if err!=nil{return independentSummary{},err}
    if manifestStat.Size()>4*1024*1024{return independentSummary{},errors.New("manifest too large")}
    raw,err:=os.ReadFile(manifestPath);if err!=nil{return independentSummary{},err}
    var manifest independentHoldoutManifest
    if err=json.Unmarshal(raw,&manifest);err!=nil{return independentSummary{},err}
    if manifest.Version!=1||len(manifest.Samples)==0||len(manifest.Samples)>5000||
       strings.TrimSpace(manifest.Source)==""||strings.TrimSpace(manifest.LabelProvenance)==""{
        return independentSummary{},errors.New("manifest must have version=1, source, labelProvenance and 1..5000 samples")
    }
    summary:=independentSummary{Timestamp:time.Now(),Source:manifest.Source,
        LabelProvenance:manifest.LabelProvenance,Results:[]independentResult{},
        Note:"Static read-only heuristic evaluation. Labels come from the independent provider, not SentinelGuard. Suspicious indicators are not proof of maliciousness. No sample executed or quarantined."}
    root,err:=filepath.Abs(filepath.Dir(manifestPath));if err!=nil{return summary,err}
    canonicalRoot,err:=filepath.EvalSymlinks(root)
    if err!=nil{return summary,err}
    for _,sample:=range manifest.Samples {
        if sample.Label!="suspicious"&&sample.Label!="benign" {
            return summary,fmt.Errorf("invalid label for %q",sample.Path)
        }
        if filepath.IsAbs(sample.Path)||sample.Path==""||strings.Contains(sample.Path,"\x00"){
            return summary,fmt.Errorf("unsafe path: %q",sample.Path)
        }
        clean:=filepath.Clean(sample.Path)
        if clean==".."||strings.HasPrefix(clean,".."+string(os.PathSeparator)) {
            return summary,fmt.Errorf("sample escapes corpus root: %q",sample.Path)
        }
        p:=filepath.Join(root,clean)
        resolved,err:=filepath.EvalSymlinks(p)
        if err!=nil{return summary,err}
        relative,err:=filepath.Rel(canonicalRoot,resolved)
        if err!=nil||relative==".."||strings.HasPrefix(relative,".."+string(os.PathSeparator))||
           filepath.IsAbs(relative) {return summary,fmt.Errorf("sample leaves canonical corpus root: %q",sample.Path)}
        st,err:=os.Lstat(p)
        if err!=nil{return summary,err}
        if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0||isReparse(p) {
            return summary,fmt.Errorf("sample is not regular file: %q",sample.Path)
        }
        if len(sample.SHA256)!=64{return summary,fmt.Errorf("missing SHA-256 for %q",sample.Path)}
        if st.Size()>512*1024*1024{
            summary.Uninspected++
            summary.Results=append(summary.Results,independentResult{Path:sample.Path,
              Label:sample.Label,Error:"File exceeds the 512-MiB holdout size limit"})
            continue
        }
        file,err:=os.Open(p)
        if err!=nil{return summary,err}
        hasher:=sha256.New()
        copied,copyErr:=io.Copy(hasher,io.LimitReader(file,512*1024*1024+1))
        closeErr:=file.Close()
        if copyErr!=nil{return summary,copyErr}
        if closeErr!=nil{return summary,closeErr}
        if copied!=st.Size(){return summary,fmt.Errorf("sample changed while being hashed: %q",sample.Path)}
        if !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)),sample.SHA256) {
            return summary,fmt.Errorf("SHA-256 mismatch for %q",sample.Path)
        }
        result:=independentResult{Path:sample.Path,Label:sample.Label}
        reasons:=[]string{}
        hit:=inspectFileProtected(p,st,func(why string){reasons=append(reasons,why)})
        if len(reasons)>0 {
            result.Error=strings.Join(reasons,"; ")
            summary.Uninspected++
        }else{
            if hit!=nil {
                result.Detected=true;result.Score=hit.Score;result.Reasons=hit.Reasons
            }
            if sample.Label=="suspicious" {
                if result.Detected{summary.TP++}else{summary.FN++}
            }else{
                if result.Detected{summary.FP++}else{summary.TN++}
            }
        }
        summary.Results=append(summary.Results,result)
    }
    return summary,nil
}
func TestIndependentHoldoutIfProvided(t *testing.T){
    manifest:=os.Getenv("SG_HOLDOUT_MANIFEST")
    if manifest=="" {t.Skip("No external labeled holdout supplied; cannot claim independent detection performance")}
    stats,err:=evaluateIndependentHoldout(manifest);if err!=nil{t.Fatal(err)}
    b,err:=json.MarshalIndent(stats,"","  ");if err!=nil{t.Fatal(err)}
    t.Logf("INDEPENDENT_HOLDOUT TP=%d FN=%d FP=%d TN=%d UNINSPECTED=%d SOURCE=%q",
        stats.TP,stats.FN,stats.FP,stats.TN,stats.Uninspected,stats.Source)
    if out:=os.Getenv("SG_HOLDOUT_REPORT");out!=""{
        if err=os.WriteFile(out,b,0600);err!=nil{t.Fatal(err)}
    }
}
func TestHoldoutHarnessBenignControl(t *testing.T) {
    dir:=t.TempDir()
    p:=filepath.Join(dir,"notes.txt")
    raw:=[]byte("This is a plain harmless test note.")
    if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)}
    hash:=sha256.Sum256(raw)
    content:=fmt.Sprintf(`{"version":1,"source":"local unit-test fixture","labelProvenance":"inert test authored for validating the evaluator","samples":[{"path":"notes.txt","label":"benign","sha256":"%x"}]}`,hash)
    m:=filepath.Join(dir,"manifest.json")
    if err:=os.WriteFile(m,[]byte(content),0600);err!=nil{t.Fatal(err)}
    stats,err:=evaluateIndependentHoldout(m);if err!=nil{t.Fatal(err)}
    if stats.TN!=1||stats.FP!=0||stats.Uninspected!=0{t.Fatalf("unexpected holdout metrics: %+v",stats)}
}
