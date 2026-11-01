# AegisMem Support Agent Domain Query Tool (Part D4)
# Sends queries to the enterprise support agent through the AegisMem-protected gateway.
# Prints: the answer, which memory version and ID it used, and that version's verification status.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [string]$Question,

    [Parameter(Mandatory = $false)]
    [string]$GatewayUrl = "http://localhost:8000",

    [Parameter(Mandatory = $false)]
    [string]$Token = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("on", "off")]
    [string]$Protection = "on",

    [Parameter(Mandatory = $false)]
    [switch]$JsonOutput
)

$ErrorActionPreference = "Stop"

# 1. Resolve Owner Token
$ownerToken = $Token
if (-not $ownerToken -and $env:AEGISMEM_OWNER_TOKEN) {
    $ownerToken = $env:AEGISMEM_OWNER_TOKEN
}

if (-not $ownerToken) {
    $rootEnv = Join-Path $PSScriptRoot "..\.env"
    if (Test-Path $rootEnv) {
        $envLines = Get-Content -Path $rootEnv -ErrorAction SilentlyContinue
        foreach ($line in $envLines) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("AEGISMEM_OWNER_TOKEN=")) {
                $val = $trimmed.Substring("AEGISMEM_OWNER_TOKEN=".Length).Trim()
                $ownerToken = $val.Trim('"', "'")
                break
            }
        }
    }
}

if (-not $ownerToken) {
    Write-Error "AEGISMEM_OWNER_TOKEN not found in environment, parameters, or .env file."
    exit 1
}

# 2. Prepare HTTP Request
$headers = @{
    "Authorization" = "Bearer $ownerToken"
    "Content-Type"  = "application/json"
}

if ($Protection -eq "off") {
    $headers["X-Aegis-Protection"] = "off"
}

$payload = @{
    question   = $Question
    protection = ($Protection -ne "off")
} | ConvertTo-Json -Compress

# 3. Query Support Agent via Gateway /chat
$chatEndpoint = "$GatewayUrl/chat"

try {
    $response = Invoke-RestMethod -Uri $chatEndpoint -Method Post -Headers $headers -Body $payload -TimeoutSec 15
} catch {
    $errorDetail = $_.Exception.Message
    if ($_.Exception.Response) {
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            $errorDetail = "$errorDetail | Body: $body"
        } catch {}
    }
    Write-Error "Failed to query support agent at $chatEndpoint : $errorDetail"
    exit 1
}

# 4. Extract Key Domain Evidence Fields
$answer = $response.answer
$memoryId = if ($response.memory_id) { $response.memory_id } else { "N/A (No memory resolved)" }
$memoryVersion = if ($response.memory_version) { "v$($response.memory_version)" } else { "N/A" }
$decision = if ($response.decision) { $response.decision } else { $null }

$isVerified = ($response.aegismem_verified -eq $true)
$verificationStatus = "UNKNOWN"
$statusColor = "Yellow"

if ($Protection -eq "off") {
    $verificationStatus = "UNPROTECTED_DIRECT_RETRIEVAL (Protection Disabled -- Unverified Memory Served)"
    $statusColor = "Red"
} elseif ($isVerified) {
    $verificationStatus = "VERIFIED (Passed AegisMem Security Gate)"
    $statusColor = "Green"
} elseif ($response.memory_used -and -not $isVerified) {
    $verificationStatus = "BLOCKED_UNVERIFIED (AegisMem Security Gate Blocked Tampered Memory)"
    $statusColor = "Red"
} else {
    $verificationStatus = "GENERAL_KNOWLEDGE (No Enterprise Memory Gate Required)"
    $statusColor = "Cyan"
}

$trustScore = if ($null -ne $response.trust_score) { $response.trust_score } else { "N/A" }
$securityReason = if ($response.security_reason) { $response.security_reason } else { "None" }

# 5. Output
if ($JsonOutput) {
    [PSCustomObject]@{
        question            = $Question
        answer              = $answer
        memory_id           = $memoryId
        memory_version      = $memoryVersion
        verification_status = $verificationStatus
        verified            = $isVerified
        decision            = $decision
        trust_score         = $trustScore
        security_reason     = $securityReason
    } | ConvertTo-Json -Depth 5
} else {
    $decisionColor = if ($decision -like "*ALLOWED*") { "Green" } else { "Magenta" }

    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                AEGISMEM SUPPORT AGENT -- DOMAIN QUERY EVIDENCE                 " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "Question:            $Question" -ForegroundColor White
    Write-Host "Memory ID:           $memoryId" -ForegroundColor Yellow
    Write-Host "Memory Version:      $memoryVersion" -ForegroundColor Yellow
    Write-Host "Verification Status: $verificationStatus" -ForegroundColor $statusColor
    Write-Host "Trust Score:         $trustScore" -ForegroundColor Gray
    if ($decision) {
        Write-Host "Policy Decision:     $decision" -ForegroundColor $decisionColor
    }
    Write-Host "Security Audit:      $securityReason" -ForegroundColor DarkGray
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Agent Answer:" -ForegroundColor Cyan
    Write-Host $answer -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}
