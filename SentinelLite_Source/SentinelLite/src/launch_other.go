//go:build !windows
package main
import "errors"
func launchReviewedExecutable(path string)error{
    return errors.New("Scan & Run launching is supported on Windows only")
}
