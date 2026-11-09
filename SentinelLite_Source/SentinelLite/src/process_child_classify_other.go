//go:build !windows

package main

func classifyObservedChildProcess(child ObservedChildProcess) ObservedChildProcess{
    child.Classification=childUnexpected
    child.ClassificationReason="Windows-only process identity verification not available."
    return child
}
