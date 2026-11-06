package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestStage12CPUNormalization(t *testing.T) {
	for _, v := range []struct {
		cpu, sec float64
		cores    int
		want     float64
	}{
		{1, 1, 1, 100}, {2, 1, 8, 25}, {0, 1, 8, 0}, {1, 0, 8, 0}, {5, 1, 2, 100},
	} {
		if got := ratePercent(v.cpu, v.sec, v.cores); got != v.want {
			t.Fatalf("CPU normalizer %+v got %.3f want %.3f", v, got, v.want)
		}
	}
}
func TestStage12NativeWindowsResourceSampler(t *testing.T) {
	cpu, mem, basis, err := readProcessResourceSample()
	if err != nil {
		t.Fatalf("native resource sample failed: %v", err)
	}
	if mem == 0 {
		t.Fatal("memory sampler returned 0")
	}
	if runtime.GOOS == "windows" && (cpu < 0 || basis != "Windows process working set") {
		t.Fatalf("bad Windows metrics cpu=%f basis=%q", cpu, basis)
	}
}

// Exercise independent readers throughout a lengthy multi-directory scan.
// Fixtures are only inert text; no programs or scripts are launched.
func TestStage12SustainedCustomScanAndConcurrentStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("long scan stress")
	}
	root := t.TempDir()
	const n = 8000
	for i := 0; i < n; i++ {
		dir := filepath.Join(root, fmt.Sprintf("group-%02d", i/100))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("item-%04d.txt", i)
		if i%100 == 0 {
			name = fmt.Sprintf("invoice-%04d.pdf.exe", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("inert testing bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	app := newApp(nil)
	ctx, err := app.begin("heuristic:custom")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.runHeuristic(ctx, "custom", root) }()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			st, fs := app.snapshot()
			if st.Files < 0 || st.Skipped < 0 || len(fs) > 3000 {
				t.Errorf("bad partial status")
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		app.stop()
		t.Fatal("sustained scan did not terminate")
	}
	app.finish(err)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	st, fs := app.snapshot()
	if st.Files != n || st.Findings != 80 || len(fs) != 80 || st.Error != "" {
		t.Fatalf("stress expected 8000 files, 80 findings; got %+v, finding count %d", st, len(fs))
	}
	if st.Resources.Samples < 1 {
		t.Fatalf("resource metrics absent after scan %+v", st.Resources)
	}
	// Verify one input remains unchanged after inspection.
	b, err := os.ReadFile(filepath.Join(root, "group-00", "item-0001.txt"))
	if err != nil || string(b) != "inert testing bytes" {
		t.Fatalf("scan modified input bytes")
	}
}

func TestStage12CancelledScanStopsTelemetry(t *testing.T) {
	app := newApp(nil)
	_, err := app.begin("heuristic:custom")
	if err != nil {
		t.Fatal(err)
	}
	app.stop()
	app.finish(context.Canceled)
	st, _ := app.snapshot()
	if st.Active || st.Error == "" {
		t.Fatalf("cancelled scan not recorded %+v", st)
	}
	samples := st.Resources.Samples
	time.Sleep(1200 * time.Millisecond)
	after, _ := app.snapshot()
	if after.Resources.Samples != samples {
		t.Fatalf("telemetry continued after scan: %d->%d", samples, after.Resources.Samples)
	}
}
