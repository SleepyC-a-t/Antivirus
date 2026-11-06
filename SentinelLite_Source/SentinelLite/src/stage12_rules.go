package main

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
)

// Stage 12 advisory rules: source is never executed. Rules require
// corroborating context and are not evidence of an active infection.
func stage12InspectableExtension(ext string) bool {
	switch ext {
	case ".ps1", ".psm1", ".cmd", ".bat", ".txt", ".js", ".jse", ".sys", ".iso", ".jpg", ".jpeg":
		return true
	}
	return false
}

var remoteMSICommand = regexp.MustCompile(`(?i)\bmsiexec(?:\.exe)?\s+(?:/i|/package)\s+https?://[^\s"'<>]+\.msi(?:\?[^\s"'<>]*)?\s+(?:[^\r\n]{0,200})?(?:/qn|/quiet)\b`)
var remoteMSIQuietFirst = regexp.MustCompile(`(?i)\bmsiexec(?:\.exe)?\s+(?:/qn|/quiet)\s+(?:/i|/package)\s+https?://[^\s"'<>]+\.msi\b`)
var copiedScreen = regexp.MustCompile(`(?i)\bcopyfromscreen\s*\(\s*[^\r\n]{1,200}\)`)
var lockedMass = regexp.MustCompile(`(?i)\b(?:all|every)\s+(?:your\s+)?files\b[^\r\n]{0,70}\b(?:end\s+in|renamed\s+to|changed\s+to)\s+\.?locked\b`)
var domainCandidate = regexp.MustCompile(`(?i)(?:[a-z0-9\p{L}-]+\.)+[a-z\p{L}]{2,}`)

// Mixed Latin/Cyrillic or Latin/Greek hostname labels are a potential
// impersonation signal when accompanied by a directive to visit the domain.
// This is only triage of a suspicious link, not a malware verdict.
func likelyMixedScriptDomain(text string) bool {
	for _, d := range domainCandidate.FindAllString(text, 24) {
		latin, other := false, false
		for _, r := range d {
			if unicode.In(r, unicode.Latin) {
				latin = true
			}
			if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
				other = true
			}
		}
		if latin && other {
			return true
		}
	}
	return false
}
func inspectStage12Content(name, ext string, data []byte, score *int, reasons *[]string) {
	if len(data) == 0 || len(data) > 2*1024*1024 {
		return
	}
	if !stage12InspectableExtension(ext) && !isThreatScriptExtension(ext) {
		return
	}
	text := decodeScriptText(data)
	lower := strings.ToLower(text)
	add := func(n int, r string) { *score += n; *reasons = append(*reasons, r) }
	switch ext {
	case ".cmd", ".bat", ".ps1", ".psm1":
		code := strings.ToLower(codeOnlyForSignals(text))
		// Existing generic rule treated a URL anywhere in a file as a remote
		// installer. Only an actual remote MSI target in the same command counts.
		if remoteMSICommand.MatchString(code) || remoteMSIQuietFirst.MatchString(code) {
			add(60, "Installer execution: msiexec directly installs a remote MSI silently (review target)")
		}
	}
	switch ext {
	case ".ps1", ".psm1":
		code := strings.ToLower(codeOnlyForSignals(text))

		// Screenshot capture alone is weak evidence: this is only Review and
		// does not indicate exfiltration or a functioning keylogger.
		if copiedScreen.MatchString(code) && strings.Contains(lower, "$size") {
			add(40, "Screen-capture API invoked from PowerShell (may be legitimate)")
		}
	case ".txt":
		// Payment-pressure instructions are possible phishing indicators,
		// but a textual invoice is not proof that malware is present.
		if strings.Contains(strings.ToLower(name), "invoice") &&
			strings.Contains(lower, "pay") && strings.Contains(lower, "urgent") &&
			strings.Contains(lower, "fee") && strings.Contains(lower, "open") {
			add(40, "Document review: invoice-themed urgent-payment instructions (may be legitimate)")
		}
		content := strings.TrimSpace(lower)
		if len(content) < 4096 {
			if (strings.Contains(content, "please visit") || strings.Contains(content, "sign in at") || strings.Contains(content, "go to")) && likelyMixedScriptDomain(text) {
				add(45, "Potential deceptive link: mixed Cyrillic/Greek and Latin characters in a requested hostname")
			}
			if lockedMass.MatchString(lower) {
				add(42, "Ransomware-related claim that all files were renamed to a locked extension (review context)")
			}
		}
	case ".jpg", ".jpeg":
		// Real JPEGs start FF D8 FF. Text masquerading as JPEG that itself
		// refers to hidden content is an advisory format anomaly only.
		jpeg := []byte{0xff, 0xd8, 0xff}
		if len(data) < 4096 && !bytes.HasPrefix(data, jpeg) &&
			strings.Contains(lower, "hidden message") && strings.Contains(lower, "pixels") {
			add(40, "Image format mismatch: JPEG-named plaintext references concealed content")
		}
	case ".sys":
		// Text masquerading as a Windows driver isn't executable driver code.
		// Only flag when content explicitly declares harmful functionality.
		if len(data) < 4096 && !isPEHeader(data) && bytes.Contains(bytes.ToLower(data), []byte("driver with malicious behavior")) {
			add(41, "Suspicious masquerade: purported driver is plaintext describing harmful behavior")
		}
	case ".iso":
		// Plaintext masquerading as an ISO with an explicit suspicious claim.
		// Genuine ISO9660 images carry CD001 near the primary volume descriptor.
		if len(data) < 4096 && !bytes.Contains(data, []byte("CD001")) &&
			strings.Contains(lower, "suspicious disk image") {
			add(40, "Misnamed disk image contains suspicious plaintext instead of an ISO structure")
		}
	}
	_ = name
}
