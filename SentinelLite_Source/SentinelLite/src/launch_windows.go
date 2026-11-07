//go:build windows
package main
import("os";"os/exec";"path/filepath")
func launchReviewedExecutable(path string)error{
    cmd:=exec.Command(path)
    cmd.Dir=filepath.Dir(path)
    if err:=cmd.Start();err!=nil{return err}
    return cmd.Process.Release()
}
var _=os.ErrNotExist
