package main

import (
    "debug/pe"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"
    "strings"
)

// Diagnostics are generated only for an explicit export request. They are
// bounded, read-only and never execute a scanned file. Ordinary JSON reports
// do not reopen any findings or attach these additional metadata fields.
const maxExportDiagnostics = 64

type ScanFileDiagnostic struct {
    FindingID string `json:"findingId"`
    Status string `json:"status"` // collected, changed, missing, nonregular, unreadable
    Extension string `json:"extension"`
    FileType string `json:"fileType"`
    SizeAtScan int64 `json:"sizeAtScan"`
    SizeAtExport int64 `json:"sizeAtExport,omitempty"`
    NameOrLocationIndicators []string `json:"nameOrLocationIndicators,omitempty"`
    SHA256 string `json:"sha256AtScan,omitempty"`
    PE *PEExportDiagnostic `json:"pe,omitempty"`
    Note string `json:"note,omitempty"`
}

type PEExportDiagnostic struct {
    Machine string `json:"machine"`
    Sections int `json:"sections"`
    ImportedSymbols int `json:"importedSymbols"`
    RelevantMemoryImports []string `json:"relevantMemoryImports,omitempty"`
    RemoteAllocation bool `json:"remoteAllocation"`
    RemoteWrite bool `json:"remoteWrite"`
    RemoteThread bool `json:"remoteThread"`
    HighEntropyExecutableSection bool `json:"highEntropyExecutableSection"`
    HighestSampledExecutableEntropy float64 `json:"highestSampledExecutableEntropy"`
    PackerLikeSection bool `json:"packerLikeSection"`
    SubstantialOverlay bool `json:"substantialOverlay"`
    SignatureStatus string `json:"signatureStatus"`
    Limitations string `json:"limitations"`
}

// This list is the bounded set of APIs already used by SentinelGuard's PE
// heuristic. We do not export arbitrary DLL names or full imports/strings.
var diagnosticMemoryAPIs = []string{
    "createremotethread", "ntallocatevirtualmemory", "ntcreatethreadex",
    "ntwritevirtualmemory", "queueuserapc", "virtualallocex", "writeprocessmemory",
}
func filenameLocationIndicators(f Finding) []string {
    indicators:=make([]string,0,3)
    for _,reason:=range f.Reasons{
        s:=strings.ToLower(reason)
        switch {
        case strings.Contains(s,"temporary folder"):
            indicators=append(indicators,"temporary-location rule")
        case strings.Contains(s,"double extension"):
            indicators=append(indicators,"double-extension rule")
        case strings.Contains(s,"misleading unicode")||strings.Contains(s,"bidirectional"):
            indicators=append(indicators,"unicode-name rule")
        }
    }
    sort.Strings(indicators)
    return indicators
}

func diagnosePEForExport(path string, size int64) *PEExportDiagnostic {
    // Avoid expensive parsing on huge or malformed binaries. The native
    // signature check is already bounded and runs only for opted-in exports.
    if size<512||size>64*1024*1024{return nil}
    image,err:=pe.Open(path)
    if err!=nil{return nil}
    defer image.Close()
    if len(image.Sections)==0||len(image.Sections)>96{return nil}
    d:=&PEExportDiagnostic{
        Machine:fmt.Sprintf("0x%04x",image.Machine),
        Sections:len(image.Sections),
        SignatureStatus:"Not checked",
        Limitations:"32 KiB maximum sampled per executable section; no code execution, full import dump or certificate publisher identity.",
    }
    var lastEnd int64
    var highest float64
    for _,section:=range image.Sections{
        end:=int64(section.Offset)+int64(section.Size)
        if end>lastEnd{lastEnd=end}
        if section.Characteristics&0x20000000==0{continue}
        sample,err:=io.ReadAll(io.LimitReader(section.Open(),32*1024))
        if err!=nil||len(sample)<4096{continue}
        entropy:=v42SectionEntropy(sample)
        if entropy>highest{highest=entropy}
        if entropy>=7.55{
            d.HighEntropyExecutableSection=true
            n:=strings.ToLower(strings.Trim(section.Name,"\x00"))
            if strings.HasPrefix(n,"upx")||strings.Contains(n,"vmp")||strings.Contains(n,"aspack"){
                d.PackerLikeSection=true
            }
        }
    }
    d.HighestSampledExecutableEntropy=float64(int(highest*100+0.5))/100
    d.SubstantialOverlay=lastEnd>0&&size>lastEnd+256*1024&&size-lastEnd>size/4
    symbols,err:=image.ImportedSymbols()
    if err==nil{
        d.ImportedSymbols=len(symbols)
        present:=make(map[string]bool)
        for _,symbol:=range symbols{
            name:=strings.ToLower(strings.SplitN(symbol,":",2)[0])
            present[name]=true
        }
        for _,api:=range diagnosticMemoryAPIs{
            if present[api]{d.RelevantMemoryImports=append(d.RelevantMemoryImports,api)}
        }
        d.RemoteAllocation=present["virtualallocex"]||present["ntallocatevirtualmemory"]
        d.RemoteWrite=present["writeprocessmemory"]||present["ntwritevirtualmemory"]
        d.RemoteThread=present["createremotethread"]||present["ntcreatethreadex"]||present["queueuserapc"]
    }
    // This is the existing in-process native WinVerifyTrust implementation:
    // it does NOT invoke PowerShell or run the target file.
    if sig,_:=verifyPESignature(path);sig!=""{d.SignatureStatus=sig}
    return d
}

func diagnoseFindingForExport(f Finding) ScanFileDiagnostic {
    d:=ScanFileDiagnostic{
        FindingID:f.ID,Status:"unavailable",
        Extension:strings.ToLower(filepath.Ext(f.Name)),
        FileType:"Unknown",SizeAtScan:f.Size,
        NameOrLocationIndicators:filenameLocationIndicators(f),
        Note:"Diagnostic metadata is gathered at export time, not at the time of the scan.",
    }
    info,err:=os.Lstat(f.Path)
    if err!=nil{
        d.Status="missing"
        d.Note="Could not inspect this finding now. No path or operating-system error text is included."
        return d
    }
    if !info.Mode().IsRegular(){
        d.Status="nonregular"
        d.Note="Only ordinary regular files are inspected. Reparse points and links are not followed."
        return d
    }
    d.SizeAtExport=info.Size()
    if info.Size()!=f.Size||!info.ModTime().Equal(f.Modified){
        d.Status="changed"
        d.Note="File size or modification time changed since scanning; no content was reread."
        return d
    }
    d.Status="collected"
    // This digest was computed while the original file was inspected; no
    // hashing of file contents is required merely to export diagnostics.
    d.SHA256=f.ReviewSHA256
    fh,err:=os.Open(f.Path)
    if err!=nil{
        d.Status="unreadable"
        d.Note="Could not open the regular file for bounded header inspection."
        return d
    }
    var hdr [4096]byte
    n,readErr:=fh.Read(hdr[:])
    _=fh.Close()
    if readErr!=nil&&readErr!=io.EOF{
        d.Status="unreadable"
        d.Note="Could not read the bounded file header."
        return d
    }
    b:=hdr[:n]
    switch{
    case isPEHeader(b):d.FileType="Windows PE"
    case len(b)>=5&&string(b[:5])=="%PDF-":d.FileType="PDF"
    case len(b)>=4&&string(b[:4])=="PK\x03\x04":d.FileType="ZIP container"
    case len(b)>=3&&string(b[:3])=="\xff\xd8\xff":d.FileType="JPEG"
    default:d.FileType="Unrecognized/other"
    }
    ext:=d.Extension
    if d.FileType=="Windows PE" && (ext==".exe"||ext==".dll"||ext==".sys"||ext==".scr"||ext==".cpl"){
        d.PE=diagnosePEForExport(f.Path,info.Size())
    }
    return d
}

func collectExportDiagnostics(findings []Finding)([]ScanFileDiagnostic,int){
    limit:=len(findings)
    if limit>maxExportDiagnostics{limit=maxExportDiagnostics}
    out:=make([]ScanFileDiagnostic,0,limit)
    for _,f:=range findings[:limit]{
        out=append(out,diagnoseFindingForExport(f))
    }
    return out,len(findings)-limit
}

// The file can still change after the Lstat check (TOCTOU): these are
// advisory snapshots, not a guarantee about which bytes were reviewed.
// Never upload this report automatically. Opt-in may include a SHA-256 hash,
// software import/API names and sensitive timestamps; redaction removes hash.
