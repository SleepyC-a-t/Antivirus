package main

import (
 "encoding/binary"
 "strings"
 "unicode/utf16"
)
// Parse the actual Windows Shell Link binary StringData fields, after
// validating its 76-byte header and optional IDList/LinkInfo structures.
// No shortcut target or argument is executed or resolved.
func structuredShortcutSignals(buf []byte)(string,string,bool){
 if len(buf)<76{return "","",false}
 flags:=binary.LittleEndian.Uint32(buf[0x14:0x18])
 offset:=76
 if flags&0x1!=0{
    if offset+2>len(buf){return "","",false}
    size:=int(binary.LittleEndian.Uint16(buf[offset:]))
    offset+=2+size
    if offset>len(buf){return "","",false}
 }
 if flags&0x2!=0{
    if offset+4>len(buf){return "","",false}
    size:=int(binary.LittleEndian.Uint32(buf[offset:]))
    if size<0x1c || size>len(buf)-offset{return "","",false}
    // Absolute ANSI local-path pointer if a structured LinkInfo exists.
    pathOffset:=int(binary.LittleEndian.Uint32(buf[offset+16:]))
    if pathOffset>0&&pathOffset<size{
       at:=offset+pathOffset
       end:=at
       for end<offset+size&&buf[end]!=0{end++}
       if end>at&&end-at<2048 { /* target supplied below via StringData if available */ }
    }
    offset+=size
 }
 unicode:=flags&0x80!=0
 var target,args string
 readField:=func()(string,bool){
    if offset+2>len(buf){return "",false}
    count:=int(binary.LittleEndian.Uint16(buf[offset:]));offset+=2
    if count<0||count>32768{return "",false}
    width:=1
    if unicode {width=2}
    if count>len(buf)/width || offset+count*width>len(buf){return "",false}
    part:=buf[offset:offset+count*width]
    offset+=count*width
    if !unicode{return string(part),true}
    units:=make([]uint16,0,count)
    for i:=0;i+1<len(part);i+=2{units=append(units,binary.LittleEndian.Uint16(part[i:i+2]))}
    return string(utf16.Decode(units)),true
 }
 for _,flag:=range []uint32{0x4,0x8,0x10,0x20,0x40}{
    if flags&flag==0{continue}
    field,ok:=readField();if !ok{return "","",false}
    if flag==0x8 {target=field}
    if flag==0x20 {args=field}
 }
 return target,args,true
}
func inspectStructuredShortcut(data []byte,score *int,reasons *[]string)bool{
 target,args,ok:=structuredShortcutSignals(data)
 if !ok{return false}
 t:=strings.ToLower(strings.TrimSpace(target))
 a:=strings.ToLower(strings.TrimSpace(args))
 if strings.Contains(t,"powershell") && (strings.Contains(a,"-enc ")||strings.Contains(a,"-encodedcommand ")){
    *score+=78
    *reasons=append(*reasons,"Parsed Shell Link target invokes PowerShell with encoded command arguments")
    if len(data)>=0x40 && binary.LittleEndian.Uint32(data[0x3c:0x40])==0 {
        *score+=12
        *reasons=append(*reasons,"Parsed shortcut requests hidden/minimized window for encoded command (corroborating)")
    }
    return true
 }
 return false
}
