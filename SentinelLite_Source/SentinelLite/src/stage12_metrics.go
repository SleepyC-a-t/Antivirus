package main

import (
	"log"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ScanResourceUsage tracks SentinelGuard's own process, not all running
// processes or a separately launched Microsoft Defender scan.
// Peaks are the largest observations sampled during the active scan.
type ScanResourceUsage struct {
	CurrentCPUPercent float64   `json:"currentCPUPercent"`
	AverageCPUPercent float64   `json:"averageCPUPercent"`
	PeakCPUPercent    float64   `json:"peakCPUPercent"`
	CurrentMemoryMiB  float64   `json:"currentMemoryMiB"`
	AverageMemoryMiB  float64   `json:"averageMemoryMiB"`
	PeakMemoryMiB     float64   `json:"peakMemoryMiB"`
	Samples           int64     `json:"samples"`
	MemoryBasis       string    `json:"memoryBasis"`
	CPUAvailable      bool      `json:"cpuAvailable"`
	LastSample        time.Time `json:"lastSample"`
}

func capPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
func ratePercent(cpuDelta, elapsed float64, logicalCPUs int) float64 {
	if logicalCPUs <= 0 || elapsed <= 0 {
		return 0
	}
	return capPercent(100 * cpuDelta / (elapsed * float64(logicalCPUs)))
}

// resetMetricsLocked is invoked from App.begin while holding a.mu.
func (a *App) resetMetricsLocked() {
	cpu, mem, kind, err := readProcessResourceSample()
	now := time.Now()
	a.resources = ScanResourceUsage{MemoryBasis: kind, CPUAvailable: err == nil, LastSample: now}
	a.lastResourceCPU = cpu
	a.lastResourceAt = now
	a.childSeen = make(map[uint32]ObservedChildProcess)
	a.cpuObservations = 0
	a.memObservations = 0
	a.sumCPUPercent = 0
	a.sumMemoryMiB = 0
	if mem > 0 {
		miB := float64(mem) / (1024 * 1024)
		a.resources.CurrentMemoryMiB = miB
		a.resources.AverageMemoryMiB = miB
		a.resources.PeakMemoryMiB = miB
		a.resources.Samples = 1
		a.memObservations = 1
		a.sumMemoryMiB = miB
	}
	if err != nil {
		log.Printf("resource telemetry degraded: %v", err)
	}
	done := make(chan struct{})
	a.resourceDone = done
	go a.monitorResources(done)
}
func (a *App) monitorResources(done <-chan struct{}) {
    a.sampleChildProcesses(done)
    childTicker := time.NewTicker(250*time.Millisecond)
    defer childTicker.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			a.sampleResources(done)
        case <-childTicker.C:
            a.sampleChildProcesses(done)
		}
	}
}
func (a *App) sampleResources(done <-chan struct{}) {
	cpu, memory, basis, err := readProcessResourceSample()
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	// A previous scan's delayed sample must never contaminate a new scan.
	if a.resourceDone == nil || a.resourceDone != done || !a.status.Active {
		return
	}
	if basis != "" {
		a.resources.MemoryBasis = basis
	}
	elapsed := now.Sub(a.lastResourceAt).Seconds()
	if err == nil && elapsed > 0.05 {
		cpuPercent := ratePercent(cpu-a.lastResourceCPU, elapsed, runtime.NumCPU())
		a.resources.CurrentCPUPercent = cpuPercent
		a.sumCPUPercent += cpuPercent
		a.cpuObservations++
		a.resources.AverageCPUPercent = a.sumCPUPercent / float64(a.cpuObservations)
		if cpuPercent > a.resources.PeakCPUPercent {
			a.resources.PeakCPUPercent = cpuPercent
		}
		a.resources.CPUAvailable = true
	}
	a.lastResourceCPU = cpu
	a.lastResourceAt = now
	if memory > 0 {
		m := float64(memory) / (1024 * 1024)
		a.resources.CurrentMemoryMiB = m
		a.sumMemoryMiB += m
		a.memObservations++
		a.resources.AverageMemoryMiB = a.sumMemoryMiB / float64(a.memObservations)
		if m > a.resources.PeakMemoryMiB {
			a.resources.PeakMemoryMiB = m
		}
		a.resources.Samples++
	}
	a.resources.LastSample = now
}

// Finish a scan with a final snapshot before stopping the metrics goroutine.
func (a *App) stopResources() {
	a.mu.RLock()
	done := a.resourceDone
	a.mu.RUnlock()
	if done == nil {
		return
	}
	a.sampleResources(done)
    a.sampleChildProcesses(done)
	a.mu.Lock()
	if a.resourceDone == done {
		close(done)
		a.resourceDone = nil
	}
	a.mu.Unlock()
}

// Toolhelp32 is polled at scan start, every 250ms, and at scan completion.
// It can miss children that start AND exit between snapshots. A clean scan
// counter is not proof that no child was created; use ETW for strong evidence.
func (a *App) sampleChildProcesses(done <-chan struct{}) {
    entries, available, err := sampleDirectChildProcesses()
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.resourceDone != done || !a.status.Active {
        return // a delayed snapshot must not contaminate another scan
    }
    a.status.ChildProcessMonitoringAvailable = available
    if !available { return }
    if err != nil {
        if a.status.ChildProcessMonitoringError == "" {
            a.status.ChildProcessMonitoringError = err.Error()
        }
        if strings.HasPrefix(a.status.Mode,"heuristic:") && a.status.ChildProcessWarning == "" {
            a.status.ChildProcessWarning = "Unable to verify child processes during heuristic scanning: OS process sampling failed."
        }
        return
    }
    a.status.ChildProcessSampleCount++
    if a.childSeen == nil { a.childSeen = make(map[uint32]ObservedChildProcess) }
    for _, child := range entries {
        if _, exists := a.childSeen[child.PID]; exists { continue }
        a.childSeen[child.PID] = child
        a.status.ChildProcessesObserved++
        if len(a.status.ChildProcessEntries) < maxObservedChildren {
            a.status.ChildProcessEntries = append(a.status.ChildProcessEntries,child)
        } else {
            a.status.ChildProcessOmitted++
        }
    }
    names := make(map[string]struct{})
    for _, child := range a.status.ChildProcessEntries { names[child.Image] = struct{}{} }
    a.status.ChildProcessImages = a.status.ChildProcessImages[:0]
    for name := range names { a.status.ChildProcessImages = append(a.status.ChildProcessImages,name) }
    sort.Strings(a.status.ChildProcessImages)
    if a.status.ChildProcessesObserved > 0 && strings.HasPrefix(a.status.Mode,"heuristic:") {
        a.status.ChildProcessWarning = "WARNING: OS process monitor observed a direct child during heuristic scanning. Stop scanning and review this incident."
    }
}
