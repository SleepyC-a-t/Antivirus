//go:build !windows

package main

import "errors"

// Browser pairing is Windows-only: do not persist unencrypted credentials.
func encryptLocalPairing(data []byte)([]byte,error){return nil,errors.New("Windows DPAPI required")}
func decryptLocalPairing(data []byte)([]byte,error){return nil,errors.New("Windows DPAPI required")}
