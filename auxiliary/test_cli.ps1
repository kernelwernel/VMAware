#!/usr/bin/env pwsh
# CLI argument test suite for VMAware (Windows / PowerShell)

param([string]$BIN = "build\vmaware.exe")

if (-not (Test-Path $BIN)) {
    Write-Error "Binary not found: $BIN"
    exit 1
}

$script:pass = 0
$script:fail = 0

function ok([string]$desc) { Write-Host "  PASS  $desc"; $script:pass++ }
function Fail-Test([string]$desc) { Write-Host "  FAIL  $desc"; $script:fail++ }

# --no-relaunch prevents the binary from re-spawning itself via conhost.exe,
# which would make every invocation exit 0 with no capturable output.
$NR = @("--no-relaunch")

# Runs $BIN with the given args, expects exit 0
function check([string]$desc, [string[]]$binArgs) {
    $null = & $BIN @script:NR @binArgs 2>&1
    if ($LASTEXITCODE -eq 0) { ok $desc } else { Fail-Test $desc }
}

# Runs $BIN with the given args, expects a non-zero exit code
function check_fails([string]$desc, [string[]]$binArgs) {
    $null = & $BIN @script:NR @binArgs 2>&1
    if ($LASTEXITCODE -ne 0) { ok $desc } else { Fail-Test $desc }
}

# Captures stdout+stderr, expects output to match $pattern (regex)
function match_out([string]$desc, [string]$pattern, [string[]]$binArgs) {
    $out = (& $BIN @script:NR @binArgs 2>&1) -join "`n"
    if ($out -match $pattern) { ok $desc }
    else { Fail-Test "$desc  (got: $(($out -split "`n")[0]))" }
}

# Captures stdout, expects an integer in [$lo, $hi]
function range_out([string]$desc, [int]$lo, [int]$hi, [string[]]$binArgs) {
    $out = (& $BIN @script:NR @binArgs 2>$null) -join ""
    if ($LASTEXITCODE -ne 0) { Fail-Test "$desc (non-zero exit)"; return }
    if ($out -match '^\d+$' -and [int]$out -ge $lo -and [int]$out -le $hi) {
        ok $desc
    } else {
        Fail-Test "$desc  (got: $out, expected $lo-$hi)"
    }
}

Write-Host "=== vmaware CLI tests ==="
Write-Host ""

# exit codes
Write-Host "exit codes"
check       "--help exits 0"             @("--help")
check       "--version exits 0"          @("--version")
check       "--brand-list exits 0"       @("--brand-list")
check       "--detect exits 0"           @("--detect")
check       "--percent exits 0"          @("--percent")
check       "--brand exits 0"            @("--brand")
check       "--type exits 0"             @("--type")
check       "--conclusion exits 0"       @("--conclusion")
check       "--number exits 0"           @("--number")

# --stdout
$null = & $BIN @NR "--stdout" 2>&1
if ($LASTEXITCODE -le 1) { ok "--stdout exits 0 or 1" } else { Fail-Test "--stdout exits 0 or 1" }

check_fails "unknown arg exits non-zero" @("--this-arg-does-not-exist")

# short-flag aliases
Write-Host ""
Write-Host "short flag aliases"
check "-h exits 0"   @("-h")
check "-v exits 0"   @("-v")
check "-a exits 0"   @("-a", "--detect")
check "-d exits 0"   @("-d")
check "-b exits 0"   @("-b")
check "-p exits 0"   @("-p")
check "-c exits 0"   @("-c")
check "-n exits 0"   @("-n")
check "-t exits 0"   @("-t")
check "-l exits 0"   @("-l")

# output format
Write-Host ""
Write-Host "output format"
match_out   "--detect outputs 0 or 1"          '^[01]$'        @("--detect")
range_out   "--percent outputs 0-100"          0 100           @("--percent")
match_out   "--number outputs a positive int"  '^[1-9][0-9]*$' @("--number")
match_out   "--brand outputs a non-empty line" '.'             @("--brand")
match_out   "--type outputs a non-empty line"  '.'             @("--type")
match_out   "--conclusion outputs a sentence"  '.'             @("--conclusion")

# no-ansi strips escape codes
Write-Host ""
Write-Host "no-ansi"
$ansiOut = (& $BIN @NR "--no-ansi" 2>&1) -join "`n"
if ($ansiOut -match '\x1B\[') {
    Fail-Test "--no-ansi still contains ANSI escape codes"
} else {
    ok "--no-ansi output contains no ANSI escape codes"
}

# technique count
Write-Host ""
Write-Host "technique count"
$n = (& $BIN @NR "--number" 2>$null) -join ""
if ($n -match '^\d+$' -and [int]$n -gt 10) {
    ok "--number returns plausible technique count ($n)"
} else {
    Fail-Test "--number returned unexpected value: $n"
}

# mutual exclusion
Write-Host ""
Write-Host "mutual exclusion"
check_fails "--detect + --brand rejected"   @("--detect", "--brand")
check_fails "--percent + --brand rejected"  @("--percent", "--brand")
check_fails "--stdout + --detect rejected"  @("--stdout", "--detect")

# --disable: valid names
Write-Host ""
Write-Host "--disable (valid names)"
check "--disable single name works"               @("--disable", "HYPERVISOR_BIT", "--detect")
check "--disable multiple space-sep names works"  @("--disable", "HYPERVISOR_BIT", "NVRAM", "QEMU_USB", "--detect")
check "--disable comma-separated names works"     @("--disable", "HYPERVISOR_BIT,NVRAM", "--detect")
check "--disable mixed comma+space works"         @("--disable", "HYPERVISOR_BIT,", "NVRAM,", "QEMU_USB", "--detect")
check "--disable WINE (was WINE_FUNC) works"      @("--disable", "WINE", "--detect")
check "--disable SYSTEM_REGISTERS works"          @("--disable", "SYSTEM_REGISTERS", "--detect")
check "--disable UD works"                        @("--disable", "UD", "--detect")
check "--disable HYPERVISOR_HOOK works"           @("--disable", "HYPERVISOR_HOOK", "--detect")
check "--disable SINGLE_STEP works"               @("--disable", "SINGLE_STEP", "--detect")
check "--disable DBVM works"                      @("--disable", "DBVM", "--detect")

# --disable: invalid names
Write-Host ""
Write-Host "--disable (invalid names)"
check_fails "--disable bogus name fails"          @("--disable", "NOT_A_REAL_TECHNIQUE", "--detect")
check_fails "--disable MULTIPLE (setting) fails"  @("--disable", "MULTIPLE", "--detect")

# --disable reflected in general output
Write-Host ""
Write-Host "--disable reflected in general output"
$disOut = (& $BIN @NR "--no-ansi" "--disable" "HYPERVISOR_BIT" 2>&1) -join "`n"
if ($disOut -match "Skipped CPUID hypervisor bit") {
    ok "--disable HYPERVISOR_BIT shows as skipped in general output"
} else {
    Fail-Test "--disable HYPERVISOR_BIT not reflected in general output"
}

# --high-threshold
Write-Host ""
Write-Host "--high-threshold"
$pNormal = [string]((& $BIN @NR "--percent" 2>$null) -join "")
$pHigh   = [string]((& $BIN @NR "--percent" "--high-threshold" 2>$null) -join "")
$pNormal = if ($pNormal -match '^\d+$') { [int]$pNormal } else { 0 }
$pHigh   = if ($pHigh   -match '^\d+$') { [int]$pHigh   } else { 0 }
if ($pNormal -ge $pHigh) {
    ok "--high-threshold produces equal or lower percentage ($pNormal -> $pHigh)"
} else {
    Fail-Test "--high-threshold produced higher percentage ($pNormal -> $pHigh)"
}

# --all
Write-Host ""
Write-Host "--all"
check "--all --detect exits 0"  @("--all", "--detect")
check "--all --percent exits 0" @("--all", "--percent")

# --dynamic
Write-Host ""
Write-Host "--dynamic"
check "--dynamic --conclusion exits 0" @("--dynamic", "--conclusion")

# --json
Write-Host ""
Write-Host "--json"
$tmpJson = [System.IO.Path]::GetTempFileName() + ".json"
try {
    $null = & $BIN @NR "--json" "--output" $tmpJson 2>$null
    if ((Test-Path $tmpJson) -and (Get-Item $tmpJson).Length -gt 0) {
        ok "--json creates a non-empty output file"
    } else {
        Fail-Test "--json did not create an output file"
    }
    $jsonContent = if (Test-Path $tmpJson) { Get-Content $tmpJson -Raw } else { "" }
    if ($jsonContent -match '"is_detected"') {
        ok "--json output contains expected keys"
    } else {
        Fail-Test "--json output missing expected keys"
    }
} finally {
    if (Test-Path $tmpJson) { Remove-Item $tmpJson -Force }
}

# --brand-list
Write-Host ""
Write-Host "--brand-list"
$brandLines = (& $BIN @NR "--brand-list" 2>$null) | Where-Object { $_ -ne "" }
$count = $brandLines.Count
if ($count -gt 5) {
    ok "--brand-list returns multiple entries ($count lines)"
} else {
    Fail-Test "--brand-list returned too few entries ($count lines)"
}

# summary
Write-Host ""
Write-Host "==========================="
Write-Host "  Passed: $($script:pass)"
Write-Host "  Failed: $($script:fail)"
Write-Host "==========================="
if ($script:fail -ne 0) { exit 1 }
