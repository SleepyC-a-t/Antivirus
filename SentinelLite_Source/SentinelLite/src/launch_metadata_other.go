//go:build !windows
package main
import "errors"
func secureLaunchReviewedExecutable(path,digest string,size int64)error{
 return errors.New("native Windows Shell launch is required")
}
func v42VerifySignature(path string)(string,string){return "Unavailable outside Windows","Unverified"}
func v42ZoneIdentifier(path string)(string,bool,error){return "Not a Windows filesystem",false,nil}
