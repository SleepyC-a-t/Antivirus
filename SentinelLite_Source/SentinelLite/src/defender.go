package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Microsoft documents that -DisableRemediation prevents actions by this custom scan.
// Defender's independent real-time protection may still act according to system policy.
var threatLine = regexp.MustCompile(`(?i)^\s*Threat\s*:\s*(.+?)\s*$`)
var fileLine = regexp.MustCompile(`(?i)^\s*(?:file|containerfile)\s*:\s*(.+?)\s*$`)

type cappedBuffer struct {
	b   bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if c.b.Len() < c.max {
		room := c.max - c.b.Len()
		if len(p) > room {
			p = p[:room]
		}
		_, _ = c.b.Write(p)
	}
	return n, nil
}

func parseDefender(text string) []Finding {
	rows := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := []Finding{}
	name := ""
	paths := []string{}
	flush := func() {
		if name == "" {
			return
		}
		if len(paths) == 0 {
			paths = []string{"(Defender reported a threat but no file path was supplied)"}
		}
		for _, raw := range paths {
			// Defender sometimes reports nested resources inside archives.
			p := strings.TrimSpace(strings.Trim(raw, `"`))
			if idx := strings.Index(p, "->"); idx > 0 {
				p = p[:idx]
			}
			if strings.HasPrefix(strings.ToLower(p), "file:_") {
				p = p[6:]
			}
			st, err := os.Lstat(p)
			can := err == nil && st.Mode().IsRegular() && !isReparse(p)
			size := int64(0)
			f := Finding{Path: p, Name: filepath.Base(p), Source: "Microsoft Defender", Score: 140, Severity: "High", Reasons: []string{"Microsoft Defender identified: " + name, "Defender custom scan used -DisableRemediation (no cleanup requested)"}, CanQuarantine: can}
			if can {
				f.Size = st.Size()
				f.Modified = st.ModTime()
			} else {
				f.Reasons = append(f.Reasons, "Original path not accessible as a regular file; review manually")
			}
			if size > 0 {
				f.Size = size
			}
			out = append(out, f)
		}
	}
	for _, line := range rows {
		if m := threatLine.FindStringSubmatch(line); m != nil {
			flush()
			name = m[1]
			paths = nil
		} else if m := fileLine.FindStringSubmatch(line); m != nil && name != "" {
			paths = append(paths, m[1])
		}
	}
	flush()
	return out
}

func (a *App) runDefender(ctx context.Context, mode, custom string) error {
	exe := defenderEXE()
	if exe == "" {
		return errors.New("Microsoft Defender MpCmdRun.exe was not found. Use the Heuristic scan, or open Windows Security")
	}
	roots, err := scanRoots(mode, custom)
	if err != nil {
		return err
	}
	total := 0
	for i, root := range roots {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.setCurrent(fmt.Sprintf("Microsoft Defender scanning %s (%d/%d). Detailed progress is unavailable.", root, i+1, len(roots)))
		output := &cappedBuffer{max: 8 * 1024 * 1024}
		cmd := exec.CommandContext(ctx, exe, "-Scan", "-ScanType", "3", "-File", root, "-DisableRemediation")
		// Explicit Defender mode only: do not flash a console on Windows.
		configureDefenderBackground(cmd)
		cmd.Stdout = output
		cmd.Stderr = output
		runErr := cmd.Run()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		found := parseDefender(output.b.String())
		for _, f := range found {
			a.add(f)
		}
		total += len(found)
		if runErr != nil && len(found) == 0 {
			return fmt.Errorf("Defender scan failed on %s: %v. Output: %s (you may need elevated permissions or Defender may be inactive)", root, runErr, truncate(strings.TrimSpace(output.b.String()), 700))
		}
		if output.b.Len() >= output.max {
			return errors.New("Defender output exceeded the safety limit; scan output may be incomplete")
		}
	}
	if total == 0 {
		a.setCurrent("Defender finished: no threats reported for scanned locations")
	} else {
		a.setCurrent(fmt.Sprintf("Defender finished: %d threat resources reported", total))
	}
	return nil
}
