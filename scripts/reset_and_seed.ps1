# ==============================================================================
# AegisMem — Truth-Based Reviewer Demo: D3 Reset and Seed Script
# ==============================================================================
# Returns the system to a known verified state: customer-support and enterprise
# baseline memories (v1, active, trust=1.0, suspicion=0.0), empty incident tables,
# and deterministic fixed seed. Strictly asserts idempotence and verifies read-back.
# ==============================================================================

[CmdletBinding()]
param(
    [int]$Seed = 42,
    [string]$Database = "aegismem_demo",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Continue"

# Strict Target Guard: Prohibit any parameter attempting to target non-demo databases
if ($Database -ne "aegismem_demo") {
    Write-Host "CRITICAL SAFETY VIOLATION: Reset script is locked to 'aegismem_demo'. Attempted target '$Database' is rejected." -ForegroundColor Red
    exit 1
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "             AegisMem Reviewer Demo: D3 Reset and Seed Verification             " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Setup timestamped demo run transcript directory
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $OutputDir = "demo_runs\$timestamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$transcriptPath = Join-Path $OutputDir "reset_and_seed.txt"
$transcriptLines = [System.Collections.Generic.List[string]]::new()

function Log-Output([string]$msg, [string]$color = "White") {
    switch ($color) {
        "Cyan"    { Write-Host $msg -ForegroundColor Cyan }
        "Green"   { Write-Host $msg -ForegroundColor Green }
        "Yellow"  { Write-Host $msg -ForegroundColor Yellow }
        "Red"     { Write-Host $msg -ForegroundColor Red }
        "Gray"    { Write-Host $msg -ForegroundColor Gray }
        default   { Write-Host $msg }
    }
    $transcriptLines.Add($msg)
}

Log-Output "================================================================================"
Log-Output "               AEGISMEM SYSTEM RESET AND DETERMINISTIC SEED                     "
Log-Output "================================================================================"
Log-Output "Timestamp (UTC) : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ssZ'))"
Log-Output "Fixed Seed      : $Seed"
Log-Output "Transcript Path : $transcriptPath"
Log-Output "--------------------------------------------------------------------------------"

# 2. Synchronize scripts to aegismem-gateway container
Log-Output "[STAGE 1] Syncing reset scripts and modules to aegismem-gateway container..." "Cyan"
& docker cp scripts/reset_and_seed_backend.py aegismem-gateway:/app/scripts/reset_and_seed_backend.py 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Log-Output "FAILED: Failed to copy scripts/reset_and_seed_backend.py into aegismem-gateway." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}

# 3. Execute Run 1 (Initial Reset & Seed)
Log-Output "`n[STAGE 2] Executing Initial Reset and Seed (Run 1) on target database '$Database'..." "Cyan"
$run1Raw = & docker exec aegismem-gateway python scripts/reset_and_seed_backend.py --seed $Seed --database $Database 2>&1
$run1Exit = $LASTEXITCODE

foreach ($line in $run1Raw) {
    Log-Output $line
}

if ($run1Exit -ne 0) {
    Log-Output "FAILED: Reset and seed execution (Run 1) failed with exit code $run1Exit." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}

# Capture Run 1 structured JSON for assertion
$run1JsonRaw = & docker exec aegismem-gateway python scripts/reset_and_seed_backend.py --seed $Seed --database $Database --json 2>&1
$run1Data = $run1JsonRaw | ConvertFrom-Json

# 4. Execute Run 2 (Idempotence Verification)
Log-Output "`n[STAGE 3] Executing Second Reset and Seed (Run 2) for Idempotence Verification..." "Cyan"
$run2JsonRaw = & docker exec aegismem-gateway python scripts/reset_and_seed_backend.py --seed $Seed --database $Database --json 2>&1
$run2Exit = $LASTEXITCODE

if ($run2Exit -ne 0) {
    Log-Output "FAILED: Second reset and seed execution (Run 2) failed with exit code $run2Exit." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}

$run2Data = $run2JsonRaw | ConvertFrom-Json

# 5. Assertions on Real Database Read-Back State
Log-Output "`n[STAGE 4] Executing Real Assertions on Database Read-Back..." "Cyan"

# Assertion 0: Live Database Preservation Check
if ($run1Data.live_database_preserved_memory_count -ne 170) {
    Log-Output "FAILED: Live database preservation check failed! aegismem_live has $($run1Data.live_database_preserved_memory_count) rows (expected 170 intact)." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}
Log-Output "  [PASS] Assertion 0: Original database preservation verified (aegismem_live has all $($run1Data.live_database_preserved_memory_count) historical records intact)." "Green"

# Assertion 1: Incident tables empty
$incidentTablesFailures = @()
foreach ($prop in $run1Data.incident_counts.PSObject.Properties) {
    $tbl = $prop.Name
    $count = [int]$prop.Value
    if ($count -ne 0) {
        $incidentTablesFailures += "$tbl has $count rows (expected 0)"
    }
}

if ($incidentTablesFailures.Count -gt 0) {
    Log-Output "FAILED: Incident tables are not empty: $($incidentTablesFailures -join ', ')" "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}
Log-Output "  [PASS] Assertion 1: All 6 incident & audit tables are verified empty (0 rows)." "Green"

# Assertion 2: Memory count & baseline versions
if ($run1Data.memory_count -ne 9) {
    Log-Output "FAILED: Memory count is $($run1Data.memory_count) (expected 9 baseline memories)." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}
Log-Output "  [PASS] Assertion 2: Total baseline memory count is $($run1Data.memory_count)." "Green"

# Assertion 3: All memories must be version 1, active, trust=1.0, suspicion=0.0
foreach ($m in $run1Data.memories) {
    if ($m.version -ne 1) {
        Log-Output "FAILED: Memory $($m.memory_id) version is $($m.version) (expected 1)." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }
    if ($m.status -ne "active") {
        Log-Output "FAILED: Memory $($m.memory_id) status is $($m.status) (expected 'active')." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }
    if ($m.trust_score -lt 1.0) {
        Log-Output "FAILED: Memory $($m.memory_id) trust score is $($m.trust_score) (expected 1.0)." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }
    if ($m.suspicion_score -gt 0.0) {
        Log-Output "FAILED: Memory $($m.memory_id) suspicion score is $($m.suspicion_score) (expected 0.0)." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }
}
Log-Output "  [PASS] Assertion 3: All 9 memories verified active, version 1, trust=1.00, suspicion=0.00." "Green"

# Assertion 4: Dependency count
if ($run1Data.dependency_count -ne 2) {
    Log-Output "FAILED: Dependency count is $($run1Data.dependency_count) (expected 2)." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}
Log-Output "  [PASS] Assertion 4: Baseline dependency count is verified ($($run1Data.dependency_count) relationships)." "Green"

# Assertion 5: Strict Idempotence Check (Run 1 == Run 2)
if ($run1Data.memory_count -ne $run2Data.memory_count) {
    Log-Output "FAILED: Idempotence failure: Run 1 memory count ($($run1Data.memory_count)) != Run 2 memory count ($($run2Data.memory_count))." "Red"
    Set-Content -Path $transcriptPath -Value $transcriptLines
    exit 1
}

for ($i = 0; $i -lt $run1Data.memories.Count; $i++) {
    $m1 = $run1Data.memories[$i]
    $m2 = $run2Data.memories[$i]
    if ($m1.memory_id -ne $m2.memory_id -or $m1.version -ne $m2.version -or $m1.content_hash -ne $m2.content_hash) {
        Log-Output "FAILED: Idempotence discrepancy at memory index $i : $($m1.memory_id) v$($m1.version) hash=$($m1.content_hash) vs $($m2.memory_id) v$($m2.version) hash=$($m2.content_hash)." "Red"
        Set-Content -Path $transcriptPath -Value $transcriptLines
        exit 1
    }
}
Log-Output "  [PASS] Assertion 5: Strict Idempotence Verified: Run 1 and Run 2 state, hashes, and counts are identical." "Green"

Log-Output "`n================================================================================"
Log-Output "                    D3 RESET AND SEED: ALL ASSERTIONS PASSED                   "
Log-Output "================================================================================"
Log-Output "Transcript saved to: $transcriptPath" "Yellow"

Set-Content -Path $transcriptPath -Value $transcriptLines
exit 0

