# scripts/preflight.ps1
# AegisMem Deployment Preflight Truth Verifier (D1)
# Inspects live Docker Compose services dynamically, asserts status, and formats report.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "=== AegisMem Deployment Preflight Truth Audit ===" -ForegroundColor Cyan

# 1. Verify Docker Compose configuration syntax
try {
    $configCheck = docker compose config --quiet 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($configCheck) -eq $false) {
        Write-Error "FAILED: preflight: docker compose config --quiet produced warnings or failed:`n$configCheck"
        exit 1
    }
} catch {
    Write-Error "FAILED: preflight: Unable to execute docker compose config: $_"
    exit 1
}

# 2. Query running services dynamically in JSON format
$rawOutput = docker compose ps --format json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "FAILED: preflight: docker compose ps failed:`n$rawOutput"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($rawOutput)) {
    Write-Error "FAILED: preflight: No running containers found from docker compose ps."
    exit 1
}

# Parse line-delimited JSON objects or JSON array
$containers = @()
foreach ($line in ($rawOutput -split "`r?`n")) {
    $trimmed = $line.Trim()
    if ($trimmed.StartsWith("{") -and $trimmed.EndsWith("}")) {
        try {
            $parsed = $trimmed | ConvertFrom-Json
            $containers += $parsed
        } catch {}
    }
}

# Dynamically compute running service count (never hardcoded)
$computedCount = $containers.Count
if ($computedCount -eq 0) {
    Write-Error "FAILED: preflight: Computed container count is 0."
    exit 1
}

# 3. Known role definitions
$roleMap = @{
    "memory-db"         = "Live Memory DB (PostgreSQL)"
    "vault-db"          = "Trust Vault DB (Network-Segmented)"
    "aegismem-gateway"   = "FastAPI Gateway & ReadPathGate"
    "aegismem-detector"  = "Continuous Watcher & Integrity Detector"
    "aegismem-recovery"  = "TCRP Recovery Resolver Worker"
    "anchor"            = "Anchor Witness Worker"
    "support-agent"     = "Enterprise Support Agent Worker"
    "attacker"          = "Adversary Container (Debian)"
    "dashboard"         = "Reviewer Dashboard Service (React/SPA)"
}

$requiredServices = @("memory-db", "vault-db", "aegismem-gateway", "aegismem-detector", "aegismem-recovery", "anchor", "support-agent", "attacker")

# 4. Build tabular inspection rows
$rows = @()
$missingServices = @()
$unhealthyServices = @()
$securityViolations = @()

$foundServiceNames = @()

foreach ($c in $containers) {
    $svc = $c.Service
    $foundServiceNames += $svc
    $role = if ($roleMap.ContainsKey($svc)) { $roleMap[$svc] } else { "Auxiliary Service" }
    
    # Extract published ports
    $publishedList = @()
    if ($c.Publishers) {
        foreach ($p in $c.Publishers) {
            if ($p.PublishedPort -gt 0) {
                $pubHost = if ([string]::IsNullOrWhiteSpace($p.URL)) { "0.0.0.0" } else { $p.URL }
                $publishedList += "$($pubHost):$($p.PublishedPort)->$($p.TargetPort)"
            }
        }
    }
    $publishedStr = if ($publishedList.Count -gt 0) { $publishedList -join ", " } else { "None (Internal)" }

    # Health / State extraction
    $healthStr = if ([string]::IsNullOrWhiteSpace($c.Health)) { $c.State } else { "$($c.State) ($($c.Health))" }

    # Extract network name cleanly
    $netStr = if ($c.Networks) { $c.Networks -replace "^aegismem-research-main_", "" } else { "none" }

    $rows += [PSCustomObject]@{
        Service   = $svc
        Role      = $role
        Networks  = $netStr
        Published = $publishedStr
        Status    = $healthStr
    }

    # Security assertions:
    # (a) vault-db MUST have 0 published ports
    if ($svc -eq "vault-db" -and $publishedList.Count -gt 0) {
        $securityViolations += "vault-db has published ports ($publishedStr). It must be strictly internal to vault-net."
    }

    # (b) memory-db must not be bound to public 0.0.0.0
    if ($svc -eq "memory-db" -and ($publishedStr -like "*0.0.0.0*")) {
        $securityViolations += "memory-db is published on 0.0.0.0 ($publishedStr). It must bind to 127.0.0.1 only."
    }

    # Check running state
    if ($c.State -ne "running") {
        $unhealthyServices += "$svc (State: $($c.State))"
    }
}

# Assert all required services exist
foreach ($req in $requiredServices) {
    if ($foundServiceNames -notcontains $req) {
        $missingServices += $req
    }
}

# Display computed table
Write-Host "`nLive Running Containers (Computed Count: $computedCount):" -ForegroundColor Yellow
$rows | Format-Table -AutoSize | Out-String | Write-Host

# 5. Evaluate assertions
if ($missingServices.Count -gt 0) {
    Write-Host "FAILED: preflight: Missing required services: $($missingServices -join ', ')" -ForegroundColor Red
    exit 1
}

if ($unhealthyServices.Count -gt 0) {
    Write-Host "FAILED: preflight: Non-running services detected: $($unhealthyServices -join ', ')" -ForegroundColor Red
    exit 1
}

if ($securityViolations.Count -gt 0) {
    Write-Host "FAILED: preflight: Security isolation violations detected:" -ForegroundColor Red
    foreach ($v in $securityViolations) {
        Write-Host "  - $v" -ForegroundColor Red
    }
    exit 1
}

Write-Host "PASSED: preflight: All $computedCount required services are active, healthy, and network-hardened.`n" -ForegroundColor Green
exit 0

