package main

import (
    "log"
    "os"
)

// A malfunctioning content analyzer must not terminate a whole scan worker.
// The failure is recorded as an uninspected path in the exported JSON.
func inspectFileProtected(p string, info os.FileInfo, onReadError func(string)) (result *Finding) {
    defer func() {
        if incident := recover(); incident != nil {
            log.Printf("File inspection error: %v",panicAsError(incident))
            if onReadError!=nil {
                onReadError("internal content inspection error; see local diagnostics log")
            }
            result=nil
        }
    }()
    return inspectFileDetailed(p,info,onReadError)
}
