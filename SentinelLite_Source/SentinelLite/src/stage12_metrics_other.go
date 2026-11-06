//go:build !windows

package main

import "runtime"

// Non-Windows development runner fallback. Windows releases use accurate
// process working-set and CPU time counters instead of Go heap statistics.
func readProcessResourceSample() (float64, uint64, string, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return 0, m.Sys, "Go runtime memory (not whole process)", nil
}
