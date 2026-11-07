//go:build !windows

package main

func startFileChangeWatcher(roots []string, events chan<- struct{}) func() {
    // Linux CI uses the 45-second reconciliation plus explicit simulated
    // pollOnce calls; only Windows receives native directory notifications.
    return func(){}
}
