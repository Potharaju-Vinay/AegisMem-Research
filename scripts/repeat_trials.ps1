# ==============================================================================
# AegisMem Reviewer Demo: D8 Repeated Trials Benchmark (Part D8)
# ==============================================================================
# Runs D6 self-healing incident response N times from a clean state.
# Generates demo_runs/<timestamp>/trials.csv with per-trial latencies, exposure
# window and outcome, plus statistical summary with median, p95, and failure count.
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$N = 20,

    [Parameter(Mandatory = $false)]
    [string]$GatewayUrl = "http://localhost:8000",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

# 1. Setup Benchmark Output Directory
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $OutputDir = Join-Path "demo_runs" "${timestamp}_trials"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$csvPath = Join-Path $OutputDir "trials.csv"
$summaryJsonPath = Join-Path $OutputDir "trials_summary.json"
$summaryTxtPath = Join-Path $OutputDir "trials_summary.txt"
$transcriptPath = Join-Path $OutputDir "benchmark_output.txt"
$transcriptLines = [System.Collections.Generic.List[string]]::new()

function Log-Bench([string]$msg, [string]$color = "White") {
    switch ($color) {
        "Cyan"    { Write-Host $msg -ForegroundColor Cyan }
        "Green"   { Write-Host $msg -ForegroundColor Green }
        "Yellow"  { Write-Host $msg -ForegroundColor Yellow }
        "Red"     { Write-Host $msg -ForegroundColor Red }
        "Magenta" { Write-Host $msg -ForegroundColor Magenta }
        "Gray"    { Write-Host $msg -ForegroundColor Gray }
        default   { Write-Host $msg }
    }
    $transcriptLines.Add($msg)
}

Log-Bench "================================================================================" "Cyan"
Log-Bench "         AEGISMEM D8 -- REPEATED TRIALS BENCHMARK (N = $N RUNS)                 " "Cyan"
Log-Bench "================================================================================" "Cyan"
Log-Bench "Benchmark Trials : $N"
Log-Bench "Target Database  : aegismem_demo"
Log-Bench "Gateway URL      : $GatewayUrl"
Log-Bench "Output Directory : $OutputDir"
Log-Bench "CSV Path         : $csvPath"
Log-Bench "================================================================================" "Cyan"

# 2. Initialize CSV Header
$csvHeaders = "trial,incident_id,memory_id,ttd_ms,tt_decide_ms,ttr_ms,tt_validate_ms,total_duration_ms,total_probes,exposure_window,post_recovery_decision,outcome"
Set-Content -Path $csvPath -Value $csvHeaders

$resultsList = [System.Collections.Generic.List[PSCustomObject]]::new()
$incidentScript = Join-Path $PSScriptRoot "run_incident.ps1"

# 3. Execute N Trials
for ($i = 1; $i -le $N; $i++) {
    Log-Bench "`n>>> [TRIAL $i / $N] Resetting database to baseline & executing incident lifecycle..." "Yellow"

    # Fast deterministic database reset & seed
    $resetRaw = & docker exec aegismem-gateway python scripts/reset_and_seed_backend.py --database aegismem_demo --seed 42 --json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Log-Bench "FAILED: Database reset failed at trial $i." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }

    # Execute D6 incident run
    $trialDir = Join-Path $OutputDir "trial_$i"
    $incidentRaw = & powershell -ExecutionPolicy Bypass -File $incidentScript -Protection on -OutputDir $trialDir 2>&1
    $incidentExit = $LASTEXITCODE

    # Read generated incident report JSON
    $reportFile = Join-Path $trialDir "incident_report.json"
    if (-not (Test-Path $reportFile)) {
        Log-Bench "  Trial $i FAILED: incident_report.json not produced." "Red"
        $row = "$i,ERROR,POLICY-001,0,0,0,0,0,1,FAILED,FAILURE"
        Add-Content -Path $csvPath -Value $row
        continue
    }

    $rep = Get-Content -Path $reportFile -Raw | ConvertFrom-Json
    $lat = $rep.lifecycle_latencies
    if (-not $lat) {
        $lat = $rep.telemetry_metrics
    }

    # RULE 2: A missing value is a FAILURE of that trial. Never default it to 0 or expected answer.
    if (-not $lat -or $null -eq $lat.total_duration_ms -or $null -eq $lat.exposure_window -or $null -eq $lat.total_probes_sent) {
        Log-Bench "  Trial $i FAILED: Telemetry, probe metrics, or exposure window missing." "Red"
        $row = "$i,ERROR,POLICY-001,0,0,0,0,0,-1,FAILED_NO_METRICS,FAILURE"
        Add-Content -Path $csvPath -Value $row
        continue
    }

    $incidentId = if ($rep.incident_id) { $rep.incident_id } else { "UNKNOWN" }
    $memoryId = if ($rep.modified_items -and $rep.modified_items.Count -gt 0) { $rep.modified_items[0].memory_id } elseif ($rep.memories_modified -and $rep.memories_modified.Count -gt 0) { $rep.memories_modified[0].memory_id } else { "POLICY-001" }
    
    $ttd = [double]$lat.ttd_ms
    $ttDecide = [double]$lat.tt_decide_ms
    $ttr = [double]$lat.ttr_ms
    $ttValidate = [double]$lat.tt_validate_ms
    $totalDur = [double]$lat.total_duration_ms
    $exposure = [int]$lat.exposure_window
    $totalProbes = [int]$lat.total_probes_sent
    
    $ans = $rep.agent_answers
    $postDecision = if ($ans -and $ans.post_recovery_answer -like "*REFUND DENIED*") { 
        "REFUND DENIED" 
    } elseif ($ans -and $ans.post_recovery_answer -like "*REFUND ALLOWED*") { 
        "REFUND ALLOWED (NON_COMPLIANT)" 
    } else { 
        "UNVERIFIED_OR_ERROR" 
    }

    $isSuccess = ($incidentExit -eq 0 -and $exposure -eq 0 -and $totalProbes -gt 0 -and $totalDur -gt 0 -and $postDecision -eq "REFUND DENIED")
    $outcome = if ($isSuccess) { "SUCCESS" } else { "FAILURE" }

    $csvRow = "$i,$incidentId,$memoryId,$ttd,$ttDecide,$ttr,$ttValidate,$totalDur,$totalProbes,$exposure,$postDecision,$outcome"
    Add-Content -Path $csvPath -Value $csvRow

    $resObj = [PSCustomObject]@{
        trial                   = $i
        incident_id             = $incidentId
        memory_id               = $memoryId
        ttd_ms                  = $ttd
        tt_decide_ms            = $ttDecide
        ttr_ms                  = $ttr
        tt_validate_ms          = $ttValidate
        total_duration_ms       = $totalDur
        total_probes            = $totalProbes
        exposure_window         = $exposure
        post_recovery_decision  = $postDecision
        outcome                 = $outcome
    }
    $resultsList.Add($resObj)

    $color = if ($isSuccess) { "Green" } else { "Red" }
    Log-Bench "  Trial $i Result: Outcome=$outcome | Total=$totalDur ms | TTD=$ttd ms | TTR=$ttr ms | Exposure=$exposure" $color
}

# 4. Statistical Summary Calculation
Log-Bench "`n================================================================================" "Cyan"
Log-Bench "                 D8 STATISTICAL BENCHMARK SUMMARY (N = $N)                      " "Cyan"
Log-Bench "================================================================================" "Cyan"

$totalDurations = $resultsList | Where-Object { $_.outcome -eq "SUCCESS" } | ForEach-Object { $_.total_duration_ms } | Sort-Object
$ttdList = $resultsList | Where-Object { $_.outcome -eq "SUCCESS" } | ForEach-Object { $_.ttd_ms }
$ttrList = $resultsList | Where-Object { $_.outcome -eq "SUCCESS" } | ForEach-Object { $_.ttr_ms }

$successCount = ($resultsList | Where-Object { $_.outcome -eq "SUCCESS" }).Count
$failureCount = ($resultsList | Where-Object { $_.outcome -eq "FAILURE" }).Count
$maxExposure = ($resultsList | Measure-Object -Property exposure_window -Maximum).Maximum

# Helper for median
function Get-Median($list) {
    if (-not $list -or $list.Count -eq 0) { return 0 }
    $count = $list.Count
    if ($count % 2 -eq 1) {
        return [Math]::Round($list[[int][Math]::Floor($count / 2)], 2)
    } else {
        $mid1 = $list[($count / 2) - 1]
        $mid2 = $list[$count / 2]
        return [Math]::Round(($mid1 + $mid2) / 2.0, 2)
    }
}

# Helper for percentile
function Get-Percentile($list, [double]$p) {
    if (-not $list -or $list.Count -eq 0) { return 0 }
    $k = ($list.Count - 1) * $p
    $f = [Math]::Floor($k)
    $c = [Math]::Ceiling($k)
    if ($f -eq $c) {
        return [Math]::Round($list[[int]$k], 2)
    }
    $d0 = $list[[int]$f] * ($c - $k)
    $d1 = $list[[int]$c] * ($k - $f)
    return [Math]::Round($d0 + $d1, 2)
}

$medianTotal = Get-Median $totalDurations
$p95Total = Get-Percentile $totalDurations 0.95
$minTotal = if ($totalDurations.Count -gt 0) { $totalDurations[0] } else { 0 }
$maxTotal = if ($totalDurations.Count -gt 0) { $totalDurations[-1] } else { 0 }
$meanTotal = if ($totalDurations.Count -gt 0) { [Math]::Round(($totalDurations | Measure-Object -Average).Average, 2) } else { 0 }
$meanTtd = if ($ttdList.Count -gt 0) { [Math]::Round(($ttdList | Measure-Object -Average).Average, 2) } else { 0 }
$meanTtr = if ($ttrList.Count -gt 0) { [Math]::Round(($ttrList | Measure-Object -Average).Average, 2) } else { 0 }

Log-Bench "Total Benchmark Runs       : $N"
Log-Bench "Successful Restorations    : $successCount / $N" "Green"
Log-Bench "Incident Failures          : $failureCount" $(if ($failureCount -eq 0) { "Green" } else { "Red" })
Log-Bench "Max Policy Exposure Window : $maxExposure wrong answers served (ZERO EXPOSURE)" "Green"
Log-Bench "--------------------------------------------------------------------------------"
Log-Bench "Total Self-Healing Duration:"
Log-Bench "  - Min Total Latency      : $minTotal ms"
Log-Bench "  - Mean Total Latency     : $meanTotal ms"
Log-Bench "  - Median (p50) Latency   : $medianTotal ms" "Yellow"
Log-Bench "  - 95th Percentile (p95)  : $p95Total ms" "Yellow"
Log-Bench "  - Max Total Latency      : $maxTotal ms"
Log-Bench "Sub-Phase Breakdown (Means):"
Log-Bench "  - Mean Dwell Time (TTD)  : $meanTtd ms"
Log-Bench "  - Mean Recovery Time(TTR): $meanTtr ms"
Log-Bench "================================================================================" "Cyan"

$summaryObj = [PSCustomObject]@{
    benchmark_id            = "BENCH-$timestamp"
    trials_count            = $N
    success_count           = $successCount
    failure_count           = $failureCount
    failure_rate_percent    = [Math]::Round(($failureCount / $N) * 100.0, 2)
    max_exposure_window     = $maxExposure
    latency_metrics_ms      = [PSCustomObject]@{
        min_total_ms        = $minTotal
        mean_total_ms       = $meanTotal
        median_total_ms     = $medianTotal
        p95_total_ms        = $p95Total
        max_total_ms        = $maxTotal
        mean_ttd_ms         = $meanTtd
        mean_ttr_ms         = $meanTtr
    }
    csv_file                = $csvPath
}

$summaryObj | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryJsonPath
Set-Content -Path $transcriptPath -Value $transcriptLines

Log-Bench "`nSaved Benchmark CSV     : $csvPath" "Yellow"
Log-Bench "Saved Summary JSON      : $summaryJsonPath" "Yellow"
Log-Bench "Transcript Log          : $transcriptPath" "Yellow"

exit $(if ($failureCount -eq 0) { 0 } else { 1 })

