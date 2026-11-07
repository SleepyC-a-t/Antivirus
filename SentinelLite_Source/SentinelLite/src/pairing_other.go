//go:build !windows
package main
func loadProtectedPairingToken()(string,bool,error){t,e:=freshPairingToken();return t,false,e}
func rotateProtectedPairingToken()(string,error){return freshPairingToken()}
