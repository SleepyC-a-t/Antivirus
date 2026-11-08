//go:build !windows

package main

import "errors"

func openDesktop(localURL string) error {
    return errors.New(""+appEdition+" desktop is available only on Windows")
}
