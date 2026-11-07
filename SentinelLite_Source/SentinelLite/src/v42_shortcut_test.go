package main
import("encoding/binary";"unicode/utf16";"testing")
func fakeStructuredShortcut(target,args string)[]byte{
 data:=make([]byte,76)
 binary.LittleEndian.PutUint32(data[:4],0x4c)
 copy(data[4:20],[]byte{1,20,2,0,0,0,0,0,0xc0,0,0,0,0,0,0,0x46})
 binary.LittleEndian.PutUint32(data[0x14:0x18],0x8|0x20|0x80)
 appendField:=func(s string){
    u:=utf16.Encode([]rune(s))
    data=append(data,byte(len(u)),byte(len(u)>>8))
    for _,v:=range u{data=append(data,byte(v),byte(v>>8))}
 }
 appendField(target);appendField(args)
 return data
}
func TestV42StructuredShortcutTargetsAndBenignArguments(t *testing.T){
 valid:=fakeStructuredShortcut(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,"-NoProfile -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
 score:=0;reasons:=[]string{}
 inspectValidatedShortcut(valid,&score,&reasons)
 if score<70 {t.Fatalf("structured encoded-command shortcut not flagged: %d %v",score,reasons)}
 normal:=fakeStructuredShortcut(`C:\Windows\notepad.exe`,"safe.txt")
 score=0;reasons=nil
 inspectValidatedShortcut(normal,&score,&reasons)
 if score>=40{t.Fatalf("benign shortcut flagged %d",score)}
 malformed:=append([]byte(nil),valid...)
 malformed[0]=0
 score=0;reasons=nil
 inspectValidatedShortcut(malformed,&score,&reasons)
 if score!=0{t.Fatal("malformed shortcut accepted")}
}
