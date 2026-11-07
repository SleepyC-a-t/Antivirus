//go:build !windows

package main

import "errors"

func chooseExecutableFile() (string,error) {
    return "", errors.New("native executable selection is available only in Windows")
}
func chooseScanFolder() (string, error) {
    return "", errors.New("native folder picker is only available in the Windows application")
}
