//go:build !windows

package main

import "errors"

func chooseScanFolder() (string, error) {
    return "", errors.New("native folder picker is only available in the Windows application")
}
