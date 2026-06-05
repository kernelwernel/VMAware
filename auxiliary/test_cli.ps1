#!/usr/bin/env pwsh
# CLI argument test suite for VMAware (Windows / PowerShell)

param(
    [string]$BIN = "build\vmaware.exe",
    [int]$TIMEOUT_SECS = 30
)

if (-not (Test-Path $BIN)) {
    Write-Error "Binary not found: $BIN"
    exit 1
}

$script:pass = 0
$script:fail = 0

function ok([string]$desc)        { Write-Host "  PASS  $desc"; $script:pass++ }
function Fail-Test([string]$desc) { Write-Host "  FAIL  $desc"; $script:fail++ }

# --no-relaunch prevents the binary from re-spawning itself via conhost.exe,
# which would make every invocation exit 0 with no capturable output.
$NR = @("--no-relaunch")

# Runs the binary with $binArgs.  Returns ([string] output, [int] exitCode).
# exitCode is -99 on timeout.  $captureStderr controls whether stderr is merged.
function invoke_bin([string[]]$binArgs, [bool]$captureStderr = $true) {
    $tmpOut = New-TemporaryFile
    $tmpErr = New-TemporaryFile
    try {
        $proc = Start-Process `
            -FilePath               $script:BIN `
            -ArgumentList           $binArgs `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $tmpOut.FullName `
            -RedirectStandardError  $tmpErr.FullName

        $finished = $proc.WaitForExit($script:TIMEOUT_SECS * 1000)
        if (-not $finished) {
            $proc.Kill()
            return $null, -99
        }

        $out = (Get-Content $tmpOut.FullName -Raw) ?? ""
        if ($captureStderr) {
            $out += (Get-Content $tmpErr.FullName -Raw) ?? ""
        }
        return $out.TrimEnd(), $proc.ExitCode
    } finally {
        Remove-Item $tmpOut.FullName, $tmpErr.FullName -Force -ErrorAction SilentlyContinue
    }
}

function check([string]$desc, [string[]]$binArgs) {
    $out, $code = invoke_bin ($script:NR + $binArgs)
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)" }
    elseif ($code -eq 0) { ok $desc }
    else { Fail-Test $desc }
}

function check_fails([string]$desc, [string[]]$binArgs) {
    $out, $code = invoke_bin ($script:NR + $binArgs)
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)" }
    elseif ($code -ne 0) { ok $desc }
    else { Fail-Test $desc }
}

function match_out([string]$desc, [string]$pattern, [string[]]$binArgs) {
    $out, $code = invoke_bin ($script:NR + $binArgs)
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)"; return }
    if ($out -match $pattern) { ok $desc }
    else { Fail-Test "$desc  (got: $(($out -split "`n")[0]))" }
}

function range_out([string]$desc, [int]$lo, [int]$hi, [string[]]$binArgs) {
    $out, $code = invoke_bin ($script:NR + $binArgs) $false
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)"; return }
    if ($code -ne 0) { Fail-Test "$desc (non-zero exit)"; return }
    $val = $out.Trim()
    if ($val -match '^\d+$' -and [int]$val -ge $lo -and [int]$val -le $hi) {
        ok $desc
    } else {
        Fail-Test "$desc  (got: $val, expected $lo-$hi)"
    }
}

Write-Host "=== vmaware CLI tests ==="
Write-Host ""

# --- exit codes ---
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

$out, $code = invoke_bin ($NR + @("--stdout"))
if ($code -eq -99) { Fail-Test "--stdout exits 0 or 1 (timeout after ${TIMEOUT_SECS}s)" }
elseif ($code -le 1) { ok "--stdout exits 0 or 1" }
else { Fail-Test "--stdout exits 0 or 1" }

check_fails "unknown arg exits non-zero" @("--this-arg-does-not-exist")

# --- short-flag aliases ---
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

# --- output format ---
Write-Host ""
Write-Host "output format"
match_out   "--detect outputs 0 or 1"          '^[01]$'        @("--detect")
range_out   "--percent outputs 0-100"          0 100           @("--percent")
match_out   "--number outputs a positive int"  '^[1-9][0-9]*$' @("--number")
match_out   "--brand outputs a non-empty line" '.'             @("--brand")
match_out   "--type outputs a non-empty line"  '.'             @("--type")
match_out   "--conclusion outputs a sentence"  '.'             @("--conclusion")

# --- no-ansi strips escape codes ---
Write-Host ""
Write-Host "no-ansi"
$ansiOut, $_ = invoke_bin ($NR + @("--no-ansi"))
if ($ansiOut -match '\x1B\[') {
    Fail-Test "--no-ansi still contains ANSI escape codes"
} else {
    ok "--no-ansi output contains no ANSI escape codes"
}

# --- technique count ---
Write-Host ""
Write-Host "technique count"
$nOut, $_ = invoke_bin ($NR + @("--number")) $false
$n = $nOut.Trim()
if ($n -match '^\d+$' -and [int]$n -gt 10) {
    ok "--number returns plausible technique count ($n)"
} else {
    Fail-Test "--number returned unexpected value: $n"
}

# --- mutual exclusion ---
Write-Host ""
Write-Host "mutual exclusion"
check_fails "--detect + --brand rejected"   @("--detect", "--brand")
check_fails "--percent + --brand rejected"  @("--percent", "--brand")
check_fails "--stdout + --detect rejected"  @("--stdout", "--detect")

# --- --disable: valid names ---
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

# --- --disable: invalid names ---
Write-Host ""
Write-Host "--disable (invalid names)"
check_fails "--disable bogus name fails"          @("--disable", "NOT_A_REAL_TECHNIQUE", "--detect")
check_fails "--disable MULTIPLE (setting) fails"  @("--disable", "MULTIPLE", "--detect")

# --- --disable reflected in general output ---
Write-Host ""
Write-Host "--disable reflected in general output"
$disOut, $_ = invoke_bin ($NR + @("--no-ansi", "--disable", "HYPERVISOR_BIT"))
if ($disOut -match "Skipped CPUID hypervisor bit") {
    ok "--disable HYPERVISOR_BIT shows as skipped in general output"
} else {
    Fail-Test "--disable HYPERVISOR_BIT not reflected in general output"
}

# --- --high-threshold ---
Write-Host ""
Write-Host "--high-threshold"
$pNOut, $_ = invoke_bin ($NR + @("--percent")) $false
$pHOut, $_ = invoke_bin ($NR + @("--percent", "--high-threshold")) $false
$pN = if ($pNOut.Trim() -match '^\d+$') { [int]$pNOut.Trim() } else { 0 }
$pH = if ($pHOut.Trim() -match '^\d+$') { [int]$pHOut.Trim() } else { 0 }
if ($pN -ge $pH) {
    ok "--high-threshold produces equal or lower percentage ($pN -> $pH)"
} else {
    Fail-Test "--high-threshold produced higher percentage ($pN -> $pH)"
}

# --- --all ---
Write-Host ""
Write-Host "--all"
check "--all --detect exits 0"  @("--all", "--detect")
check "--all --percent exits 0" @("--all", "--percent")

# --- --dynamic ---
Write-Host ""
Write-Host "--dynamic"
check "--dynamic --conclusion exits 0" @("--dynamic", "--conclusion")

# --- --json ---
Write-Host ""
Write-Host "--json"
$tmpJson = [System.IO.Path]::GetTempFileName() + ".json"
try {
    $out, $code = invoke_bin ($NR + @("--json", "--output", $tmpJson))
    if ($code -eq -99) {
        Fail-Test "--json timed out"
        Fail-Test "--json output missing expected keys"
    } else {
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
    }
} finally {
    if (Test-Path $tmpJson) { Remove-Item $tmpJson -Force }
}

# --- --brand-list ---
Write-Host ""
Write-Host "--brand-list"
$blOut, $_ = invoke_bin ($NR + @("--brand-list")) $false
$brandLines = ($blOut -split "`n") | Where-Object { $_.Trim() -ne "" }
$count = $brandLines.Count
if ($count -gt 5) {
    ok "--brand-list returns multiple entries ($count lines)"
} else {
    Fail-Test "--brand-list returned too few entries ($count lines)"
}

# --- summary ---
Write-Host ""
Write-Host "==========================="
Write-Host "  Passed: $($script:pass)"
Write-Host "  Failed: $($script:fail)"
Write-Host "==========================="
if ($script:fail -ne 0) { exit 1 }
