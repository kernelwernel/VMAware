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

# Runs the binary with $binArgs.  Returns ([string] output, [int] exitCode).
# exitCode is -99 on timeout.  $captureStderr controls whether stderr is merged.
#
# CreateNoWindow=$true detaches the child from any attached console so the MSVC
# runtime uses WriteFile (not WriteConsoleW) for std::cout.  Without it, when
# the parent process has a console, the CRT routes output through WriteConsoleW
# which silently fails on a pipe handle and the captured output is empty.
function invoke_bin([string[]]$binArgs, [bool]$captureStderr = $true, [int]$timeoutMs = -1) {
    if ($timeoutMs -lt 0) { $timeoutMs = $script:TIMEOUT_SECS * 1000 }

    $psi = [System.Diagnostics.ProcessStartInfo]::new($script:BIN)
    foreach ($a in $binArgs) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $proc    = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($timeoutMs)) {
        $proc.Kill()
        return $null, -99
    }

    $out = $outTask.Result
    if ($captureStderr) { $out += $errTask.Result }
    return $out.TrimEnd(), $proc.ExitCode
}

function check([string]$desc, [string[]]$binArgs) {
    $out, $code = invoke_bin $binArgs
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)" }
    elseif ($code -eq 0) { ok $desc }
    else { Fail-Test $desc }
}

function check_fails([string]$desc, [string[]]$binArgs) {
    $out, $code = invoke_bin $binArgs
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)" }
    elseif ($code -ne 0) { ok $desc }
    else { Fail-Test $desc }
}

function match_out([string]$desc, [string]$pattern, [string[]]$binArgs) {
    $out, $code = invoke_bin $binArgs
    if ($code -eq -99) { Fail-Test "$desc (timeout after ${TIMEOUT_SECS}s)"; return }
    if ($out -match $pattern) { ok $desc }
    else { Fail-Test "$desc  (got: $(($out -split "`n")[0]))" }
}

function range_out([string]$desc, [int]$lo, [int]$hi, [string[]]$binArgs) {
    $out, $code = invoke_bin $binArgs $false
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

# exit codes (cheap flags only — no full detection scan)
Write-Host "exit codes"
check       "--help exits 0"             @("--help")
check       "--version exits 0"          @("--version")
check       "--brand-list exits 0"       @("--brand-list")
check       "--number exits 0"           @("--number")
check_fails "unknown arg exits non-zero" @("--this-arg-does-not-exist")

# short-flag aliases (cheap flags only)
Write-Host ""
Write-Host "short flag aliases"
check "-h exits 0"   @("-h")
check "-v exits 0"   @("-v")
check "-n exits 0"   @("-n")
check "-l exits 0"   @("-l")

# output format + exit codes for full-scan flags (one scan per flag)
Write-Host ""
Write-Host "output format"
match_out   "--detect outputs 0 or 1"          '^[01]$'        @("--detect")
range_out   "--percent outputs 0-100"          0 100           @("--percent")
match_out   "--number outputs a positive int"  '^[1-9][0-9]*$' @("--number")

$out, $code = invoke_bin @("--stdout")
if ($code -eq -99) { Fail-Test "--stdout exits 0 or 1 (timeout after ${TIMEOUT_SECS}s)" }
elseif ($code -le 1) { ok "--stdout exits 0 or 1" }
else { Fail-Test "--stdout exits 0 or 1" }

match_out   "--detect outputs 0 or 1"          '^[01]$'        @("-d")
match_out   "--percent outputs 0-100"          '^[0-9]+$'      @("-p")

$out, $code = invoke_bin @("-s")
if ($code -eq -99) { Fail-Test "-s exits 0 or 1 (timeout after ${TIMEOUT_SECS}s)" }
elseif ($code -le 1) { ok "-s exits 0 or 1" }
else { Fail-Test "-s exits 0 or 1" }

# -b/-t/-c/-a: just verify the flag is recognised (pair with -n so NUMBER short-circuits
# before the full detection scan, meaning no scan is triggered)
check "-b recognised" @("-b", "-n")
check "-t recognised" @("-t", "-n")
check "-c recognised" @("-c", "-n")
check "-a recognised" @("-a", "-n")

# One general-output scan covers: no-ansi, brand/type/conclusion presence, and
# --disable reflection — combining these avoids a second full-scan invocation.
Write-Host ""
Write-Host "no-ansi + general output + disable reflection"
$genOut, $_ = invoke_bin @("--no-ansi", "--disable", "HYPERVISOR_BIT")
if ($genOut -match '\x1B\[') {
    Fail-Test "--no-ansi still contains ANSI escape codes"
} else {
    ok "--no-ansi output contains no ANSI escape codes"
}
if ($genOut -match 'VM brand:')   { ok "--brand produces output in general run"      } else { Fail-Test "--brand missing from general output"      }
if ($genOut -match 'VM type:')    { ok "--type produces output in general run"       } else { Fail-Test "--type missing from general output"       }
if ($genOut -match 'CONCLUSION:') { ok "--conclusion produces output in general run" } else { Fail-Test "--conclusion missing from general output" }
if ($genOut -match "Skipped CPUID hypervisor bit") {
    ok "--disable HYPERVISOR_BIT shows as skipped in general output"
} else {
    Fail-Test "--disable HYPERVISOR_BIT not reflected in general output"
}

# technique count
Write-Host ""
Write-Host "technique count"
$nOut, $_ = invoke_bin @("--number") $false
$n = $nOut.Trim()
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

# --high-threshold
Write-Host ""
Write-Host "--high-threshold"
$pNOut, $_ = invoke_bin @("--percent") $false
$pHOut, $_ = invoke_bin @("--percent", "--high-threshold") $false
$pN = if ($pNOut.Trim() -match '^\d+$') { [int]$pNOut.Trim() } else { 0 }
$pH = if ($pHOut.Trim() -match '^\d+$') { [int]$pHOut.Trim() } else { 0 }
if ($pN -ge $pH) {
    ok "--high-threshold produces equal or lower percentage ($pN -> $pH)"
} else {
    Fail-Test "--high-threshold produced higher percentage ($pN -> $pH)"
}

# --all
Write-Host ""
Write-Host "--all"
check "--all --detect exits 0"  @("--all", "--detect")
check "--all --percent exits 0" @("--all", "--percent")

# --dynamic
Write-Host ""
Write-Host "--dynamic"
check "--dynamic --detect exits 0" @("--dynamic", "--detect")

# --json
Write-Host ""
Write-Host "--json"
$tmpJson = [System.IO.Path]::GetTempFileName() + ".json"
try {
    $out, $code = invoke_bin @("--json", "--output", $tmpJson) $true 30000
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

# --brand-list
Write-Host ""
Write-Host "--brand-list"
$blOut, $_ = invoke_bin @("--brand-list") $false
$brandLines = ($blOut -split "`n") | Where-Object { $_.Trim() -ne "" }
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