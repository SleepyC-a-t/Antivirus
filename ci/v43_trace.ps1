param(
 [Parameter(Mandatory=$true)][string]$Baseline,
 [Parameter(Mandatory=$true)][string]$Patched,
 [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Output | Out-Null
# Both checkouts receive THE SAME read-only scanner probe. The only
# instrumentation is an atomic counter at v42VerifySignature entry.
$src = Join-Path $Patched 'ci/v43_forensic_scan_test.go'
if (!(Test-Path $src)) { throw 'missing frozen common probe' }
$survey = Join-Path $Patched 'SentinelLite_Source/SentinelLite/src/v42_windows_benign_corpus_test.go'
foreach ($pair in @(@('old',$Baseline),@('patched',$Patched))) {
 $tag,$root=$pair
 $dir=Join-Path $root 'SentinelLite_Source/SentinelLite/src'
 Copy-Item $src (Join-Path $dir 'v43_forensic_scan_test.go') -Force
 if ($tag -ne 'patched') {
   Copy-Item $survey (Join-Path $dir 'v42_windows_benign_corpus_test.go') -Force
 }
 $metadata=Join-Path $dir 'launch_metadata_windows.go'
 $raw=[IO.File]::ReadAllText($metadata)
 $needle='func v42VerifySignature(path string)(string,string){'
 if (!$raw.Contains($needle)) { throw "$tag signature instrumentation anchor absent" }
 $raw=$raw.Replace($needle,"$needle`n    forensicSignatureCalls.Add(1) // CI-only instrumentation`n")
 [IO.File]::WriteAllText($metadata,$raw)
}

function Get-EventPayload([xml]$xml) {
 $map=@{}
 foreach($d in @($xml.Event.EventData.Data)) {
   $name=[string]$d.Name
   if (!$name) {$name="Field$($map.Count)"}
   $map[$name]=[string]$d.'#text'
 }
 return $map
}
foreach ($pair in @(@('old',$Baseline),@('patched',$Patched))) {
 $tag,$root=$pair
 $outputFolder=Join-Path $Output $tag
 New-Item -ItemType Directory -Force -Path $outputFolder | Out-Null
 $session="SGForensic-$tag"
 $etl=Join-Path $outputFolder 'kernel-process.etl'
 $csv=Join-Path $outputFolder 'tracerpt.csv'
 $dir=Join-Path $root 'SentinelLite_Source/SentinelLite/src'
 $provider='Microsoft-Windows-Kernel-Process'
 $enabled=$false
 try {
   & logman create trace $session -p $provider 0xFFFFFFFF 5 -o $etl -ow
   if ($LASTEXITCODE -ne 0) {throw "logman create failed: $LASTEXITCODE"}
   & logman start $session -ets
   if ($LASTEXITCODE -ne 0) {throw "logman start failed: $LASTEXITCODE"}
   $enabled=$true
   Push-Location $dir
   try {
     $env:SENTINELGUARD_PYTHON_ROOT=(python -c "import sys;print(sys.prefix)")
     $env:SENTINELGUARD_NPM_ROOT=(npm root -g)
     $env:SG_FOR_FORENSIC='1'
     & go test -count=1 -v -run '^TestForensicFullInspectionReadOnly$' . *>&1 |
       Tee-Object -FilePath (Join-Path $outputFolder 'go-test.log')
     if($LASTEXITCODE -ne 0){throw "$tag forensic scan failed"}
   } finally {Pop-Location}
 } finally {
   if($enabled){& logman stop $session -ets}
   & logman delete $session
 }
 if(!(Test-Path $etl)){throw "$tag ETW trace was not recorded"}
 # Keep raw ETW and tracerpt CSV even if event field parsing varies by OS.
 & tracerpt $etl -of CSV -o $csv -y 2>&1 |
    Out-File (Join-Path $outputFolder 'tracerpt-output.log')
 $parsed=@()
 $counts=@{}
 try {
   $events=@(Get-WinEvent -Path $etl -Oldest -ErrorAction Stop)
   foreach($evt in $events){
     if($evt.ProviderName -notlike '*Kernel-Process*') {continue}
     $payload=Get-EventPayload ([xml]$evt.ToXml())
     $image=($payload.ImageName,$payload.ImageFileName,$payload.ProcessName,$payload.ImagePath |
          Where-Object {$_}|Select-Object -First 1)
     $cmdline=($payload.CommandLine,$payload.ProcessCommandLine |
          Where-Object {$_}|Select-Object -First 1)
     $parent=($payload.ParentProcessID,$payload.ParentID,$payload.ParentProcessId |
          Where-Object {$_}|Select-Object -First 1)
     $pidField=($payload.ProcessID,$payload.ProcessId |
          Where-Object {$_}|Select-Object -First 1)
     $record=[ordered]@{eventId=$evt.Id;time=$evt.TimeCreated.ToString('o');image=$image;
          commandLine=$cmdline;parentPID=$parent;pid=$pidField;fields=$payload}
     if($evt.Id -eq 1 -or $image) {
       $parsed += $record
       $key=if($image){[IO.Path]::GetFileName($image).ToLowerInvariant()}else{"id_$($evt.Id)"}
       if(!$counts.ContainsKey($key)){$counts[$key]=0};$counts[$key]++
     }
   }
 } catch {
   "Get-WinEvent parse unavailable: $($_.Exception.Message)" |
     Set-Content (Join-Path $outputFolder 'event-parse-error.txt')
 }
 $parsed|ConvertTo-Json -Depth 7 -Compress |Set-Content -Encoding UTF8 (Join-Path $outputFolder 'events.json')
 $log=Get-Content (Join-Path $outputFolder 'go-test.log') -Raw
 $matches=[regex]::Matches($log,'FORENSIC_SURVEY files=(\d+) flags=(\d+) verifySignatureCalls=(\d+) processID=(\d+)')
 if($matches.Count -ne 1){throw "$tag missing FORENSIC_SURVEY counter evidence"}
 $f=$matches[0].Groups
 $control=[regex]::Match($log,'FORENSIC_FINAL surveyCalls=(\d+) directControlCalls=(\d+) total=(\d+)')
 $summary=[ordered]@{
   build=$tag;surveyFiles=[int]$f[1].Value;surveyFlagged=[int]$f[2].Value;
   signatureCallsFromSurvey=[int]$f[3].Value;testProcessPID=[int]$f[4].Value;
   signatureCallsFromDirectControl=if($control.Success){[int]$control.Groups[2].Value}else{$null};
   recordedETWEvents=$parsed.Count;spawnedImages=$counts;
   commandsMayBeUnavailable=$true;etwPath=$etl;csvPath=$csv;
   noClaimsIfProviderUnavailable='Raw ETW evidence must be interpreted independently'
 }
 $summary|ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $outputFolder 'summary.json')
 Write-Host "FORENSIC_RESULT $($summary|ConvertTo-Json -Compress -Depth 8)"
}
# Do not assert a fabricated 0-vs-positive result: upload evidence and let
# separate evidence review decide if real PE samples exercised the path.
