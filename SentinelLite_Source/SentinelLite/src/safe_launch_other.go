//go:build !windows

package main

func confirmProgramLaunch(path string,score int,reasons []string) bool {
    return false
}
