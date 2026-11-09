//go:build !windows
package main
import("context";"time")
func activeNativeWatcherMode()string{return "periodic filesystem reconciliation"}
func activeReconcileInterval()time.Duration{return 4*time.Second}
func watchActiveDirectory(ctx context.Context,root string,kick chan<-struct{}){}
