//go:build !windows

package main

import "errors"

func openDesktop(localURL string) error {
    return errors.New("SentinelGuard 4.0 desktop is available only on Windows")
}
