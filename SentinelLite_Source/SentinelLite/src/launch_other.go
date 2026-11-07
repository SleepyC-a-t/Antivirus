//go:build !windows
package main
import "errors"
func withLaunchFileLock(path string,fn func()error)error{return fn()}
func executableZone(path string)(string,error){return "Not available on this platform",nil}
func verifiedSignatureStatus(path string)(string,string){return "Not available","Not available"}
func launchReviewedExecutable(path string)error{return errors.New("Scan & Run launching is supported on Windows only")}
