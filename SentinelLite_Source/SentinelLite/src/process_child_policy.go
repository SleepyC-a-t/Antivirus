package main

import (
    "fmt"
    "path/filepath"
    "regexp"
    "strings"
)

// Never allowlist only by process name. A successful WinVerifyTrust result
// alone does not establish the Microsoft *publisher*; we also require the
// native process path to be under a machine-administered Evergreen runtime
// installation root and to match its exact executable layout.
//
// The roots MUST come from protected machine registry values on Windows, not
// caller-supplied environment variables.
const (
    childExpectedWebView = "expected-webview2"
    childUnverifiedWebView = "unverified-webview2"
    childUnexpected = "unexpected"
)
var webViewRuntimeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

func isOfficialWebViewRuntimePath(path string, machineRoots []string) bool {
    if path == "" || filepath.Base(path)== "." || strings.HasPrefix(path, `\\`) {
        return false
    }
    clean := filepath.Clean(path)
    if !filepath.IsAbs(clean) { return false }
    for _, root := range machineRoots {
        if root == "" || !filepath.IsAbs(root) { continue }
        relative, err := filepath.Rel(filepath.Clean(root), clean)
        if err!=nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
            continue
        }
        parts := strings.Split(filepath.ToSlash(relative),"/")
        if len(parts)!=5 {continue}
        if strings.EqualFold(parts[0],"Microsoft") &&
           strings.EqualFold(parts[1],"EdgeWebView") &&
           strings.EqualFold(parts[2],"Application") &&
           webViewRuntimeVersion.MatchString(parts[3]) &&
           strings.EqualFold(parts[4],"msedgewebview2.exe") {
            return true
        }
    }
    return false
}

// This pure function makes trust rules testable without running a process.
// A spoofed filename, unsigned file, user-writable installation, or absent
// process path is ALWAYS unverified/unexpected, never auto-cleared.
func classifyChildEvidence(image, path, signature string, machineRoots []string) (string,string) {
    if !strings.EqualFold(strings.TrimSpace(image), "msedgewebview2.exe") {
        return childUnexpected,"Not a recognized WebView2 interface child."
    }
    if path == "" {
        return childUnverifiedWebView,"Could not query the full process image path; name alone is insufficient."
    }
    if !isOfficialWebViewRuntimePath(path,machineRoots) {
        return childUnverifiedWebView,"Image is not in a recognized machine-managed Edge WebView2 Runtime installation."
    }
    // This is intentionally the *exact* successful offline native trust
    // status. Untrusted, unverifiable, revoked/unknown or busy checks fail
    // closed; catalog signing isn't yet resolved by SentinelGuard.
    if signature != "Trusted embedded signature (offline; revocation not checked)" {
        return childUnverifiedWebView,fmt.Sprintf("Runtime location matched, but embedded signature did not verify (%s).",signature)
    }
    return childExpectedWebView,"Native Authenticode trust succeeded at the machine-managed Edge WebView2 Runtime path; Microsoft publisher identity is not independently extracted."
}
