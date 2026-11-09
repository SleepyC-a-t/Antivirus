//go:build !windows

package main

import "errors"

func chooseScanFolder() (string, error) {
    return "", errors.New("native folder picker is only available in the Windows application")
}

func chooseScanExecutable()(string,error){return "",errors.New("native executable picker requires Windows")}
