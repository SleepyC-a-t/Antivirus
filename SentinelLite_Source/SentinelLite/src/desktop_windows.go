//go:build windows

package main

import (
    "errors"
    "runtime"
    "github.com/jchv/go-webview2"
)

// openDesktop uses Windows' installed Microsoft Edge WebView2 runtime to
// render the existing local UI inside an ordinary, resizable desktop window.
// It does not open an external browser and never navigates to remote content.
func openDesktop(localURL string) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    w:=webview2.NewWithOptions(webview2.WebViewOptions{
        Debug:false,
        AutoFocus:true,
        WindowOptions:webview2.WindowOptions{
            Title:appEdition+" — Security Center",
            Width:1440,
            Height:930,
            Center:true,
        },
    })
    if w==nil {
        return errors.New("Microsoft Edge WebView2 Runtime could not start; install or repair it through Microsoft")
    }
    defer w.Destroy()
    w.SetSize(1100,730,webview2.HintMin)
    w.Navigate(localURL)
    // Runs a real native Windows GUI event loop. When the window closes,
    // control returns and main() shuts down active monitoring and the API.
    w.Run()
    return nil
}
