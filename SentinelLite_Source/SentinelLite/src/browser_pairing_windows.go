//go:build windows

package main

import (
    "errors"
    "syscall"
    "unsafe"
)

type dataBlob struct{
    Size uint32
    Data *byte
}
var pairCrypt32=syscall.NewLazyDLL("crypt32.dll")
var protectData=pairCrypt32.NewProc("CryptProtectData")
var unprotectData=pairCrypt32.NewProc("CryptUnprotectData")
var pairLocalFree=syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

func protectLocalData(data []byte,decrypt bool)([]byte,error){
    if len(data)==0{return nil,errors.New("empty pairing record")}
    in:=dataBlob{Size:uint32(len(data)),Data:&data[0]}
    var out dataBlob
    const uiForbidden=0x1
    var ok uintptr
    var lastErr error
    if decrypt {
        ok,_,lastErr=unprotectData.Call(uintptr(unsafe.Pointer(&in)),0,0,0,0,uiForbidden,uintptr(unsafe.Pointer(&out)))
    }else{
        ok,_,lastErr=protectData.Call(uintptr(unsafe.Pointer(&in)),0,0,0,0,uiForbidden,uintptr(unsafe.Pointer(&out)))
    }
    if ok==0 {return nil,lastErr}
    if out.Data==nil{return nil,errors.New("Windows DPAPI produced empty output")}
    defer pairLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
    result:=append([]byte{},unsafe.Slice(out.Data,int(out.Size))...)
    return result,nil
}
func encryptLocalPairing(data []byte)([]byte,error){return protectLocalData(data,false)}
func decryptLocalPairing(data []byte)([]byte,error){return protectLocalData(data,true)}
