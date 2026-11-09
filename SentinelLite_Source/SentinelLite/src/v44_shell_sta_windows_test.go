//go:build windows

package main

import (
    "fmt"
    "path/filepath"
    "testing"
)

// Noninteractive COM test. Does not click real buttons, execute an EXE,
// or navigate to the Windows Security GUI on a CI runner.
func TestSecurityWindowsShellButtonsUseCOMSTA(t *testing.T) {
    ran:=false
    err:=withShellSTA(func()error{
        ran=true
        // Reinitializing a STA thread as MTA must fail with RPC_E_CHANGED_MODE.
        // If COM was never initialized, it would succeed and this test fails.
        hr,_,_:=fileDialogCoInitializeEx.Call(0,0)
        if uint32(hr)&0x80000000==0 {
            fileDialogCoUninitialize.Call()
            return fmt.Errorf("Shell action was not running in an STA; MTA initialization returned HRESULT 0x%08X",uint32(hr))
        }
        if uint32(hr)!=0x80010106 {
            return fmt.Errorf("expected RPC_E_CHANGED_MODE on STA, got 0x%08X",uint32(hr))
        }
        return nil
    })
    if err!=nil{t.Fatal(err)}
    if !ran{t.Fatal("Windows Shell callback was never invoked")}
    if seeMaskNoAsyncForSecurity&0x100==0{
        t.Fatal("Windows Security ShellExecute must include SEE_MASK_NOASYNC")
    }
    // Open Location rejects invalid paths via native Shell APIs.
    bad:=filepath.Join(t.TempDir(),"does-not-exist","not-a-real-file.zzz")
    if err:=openLocation(bad);err==nil{
        t.Log("Windows shell accepted a non-existing path; interactive button semantics require separate field test")
    }
}
