//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getFileAttributes = kernel32.NewProc("GetFileAttributesW")
var getDriveType = kernel32.NewProc("GetDriveTypeW")
var user32 = syscall.NewLazyDLL("user32.dll")
var messageBox = user32.NewProc("MessageBoxW")

func isReparse(path string) bool {
	u, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attr, _, _ := getFileAttributes.Call(uintptr(unsafe.Pointer(u)))
	return attr != 0xffffffff && (attr&0x400) != 0
}
func fixedAndRemovableDrives() []string {
	out := []string{}
	for c := 'C'; c <= 'Z'; c++ {
		root := string(c) + ":\\"
		p, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(p)))
		if t == 2 || t == 3 {
			if _, err := os.Stat(root); err == nil {
				out = append(out, root)
			}
		}
	}
	return out
}
func openBrowser(url string) error {
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}
func openLocation(path string) error { return exec.Command("explorer.exe", "/select,"+path).Start() }
func openWindowsSecurity() error {
	return exec.Command("explorer.exe", "windowsdefender://threat/").Start()
}
func reportStartupError(err string) {
	title, _ := syscall.UTF16PtrFromString("SentinelLite - error")
	body, _ := syscall.UTF16PtrFromString(err)
	messageBox.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}
func defenderEXE() string {
	roots := []string{filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows Defender", "Platform")}
	for _, root := range roots {
		ents, err := os.ReadDir(root)
		if err == nil {
			versions := []string{}
			for _, e := range ents {
				if e.IsDir() {
					versions = append(versions, e.Name())
				}
			}
			// lexical versions are fine for all current Defender platform branches.
			for i := 0; i < len(versions); i++ {
				for j := i + 1; j < len(versions); j++ {
					if strings.Compare(versions[i], versions[j]) < 0 {
						versions[i], versions[j] = versions[j], versions[i]
					}
				}
			}
			for _, ver := range versions {
				path := filepath.Join(root, ver, "MpCmdRun.exe")
				if st, err := os.Stat(path); err == nil && !st.IsDir() {
					return path
				}
			}
		}
	}
	p := filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MpCmdRun.exe")
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}
