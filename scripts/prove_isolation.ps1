# scripts/prove_isolation.ps1
# AegisMem Network-Segmented Isolation Proof (D2)
# Executes real connection tests across network zones and asserts strict isolation boundaries.

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

# Create timestamped run folder
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$runDir = Join-Path "demo_runs" $timestamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$transcriptPath = Join-Path $runDir "isolation.txt"

# Transcript logger helper
function Log-Output {
    param([string]$text, [string]$color = "White")
    Write-Host $text -ForegroundColor $color
    Add-Content -Path $transcriptPath -Value $text
}

Log-Output "=================================================================" "Cyan"
Log-Output " AegisMem Network-Segmented Isolation Verification (D2)" "Cyan"
Log-Output " Timestamp: $timestamp" "Cyan"
Log-Output " Architecture: Network-Segmented Multi-Zone Deployment" "Cyan"
Log-Output "=================================================================`n" "Cyan"

$allPassed = $true

# -------------------------------------------------------------------------
# Test (a): Attacker container -> Vault Database (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test A] Attacker container to Vault Database (vault-db:5432)" "Yellow"
$cmdA = 'docker exec aegismem-attacker python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect((\"vault-db\", 5432))" 2>&1'
Log-Output "Command: $cmdA"
$outA = & cmd.exe /c $cmdA
$exitA = $LASTEXITCODE
Log-Output "Result (Exit Code $exitA):`n$($outA -join "`n")"

if ($exitA -ne 0) {
    Log-Output "ASSERTION PASSED: Attacker cannot reach vault-db (Connection blocked as expected).`n" "Green"
} else {
    Log-Output "FAILED: test_a: Attacker was able to connect to vault-db! Isolation boundary breached.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (b): Attacker container -> Anchor Witness (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test B] Attacker container to Anchor Witness (anchor:8000)" "Yellow"
$cmdB = 'docker exec aegismem-attacker python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect((\"anchor\", 8000))" 2>&1'
Log-Output "Command: $cmdB"
$outB = & cmd.exe /c $cmdB
$exitB = $LASTEXITCODE
Log-Output "Result (Exit Code $exitB):`n$($outB -join "`n")"

if ($exitB -ne 0) {
    Log-Output "ASSERTION PASSED: Attacker cannot reach anchor witness (Connection blocked as expected).`n" "Green"
} else {
    Log-Output "FAILED: test_b: Attacker was able to connect to anchor! Isolation boundary breached.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (c): Host -> Vault Port (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test C] Host workstation to Vault Port (127.0.0.1:5433)" "Yellow"
Log-Output "Testing TCP connection from host to 127.0.0.1:5433..."

$client = New-Object System.Net.Sockets.TcpClient
$connectedC = $false
try {
    $async = $client.BeginConnect("127.0.0.1", 5433, $null, $null)
    $wait = $async.AsyncWaitHandle.WaitOne(1500, $false)
    if ($wait -and $client.Connected) {
        $client.EndConnect($async)
        $connectedC = $true
    }
} catch {
    $connectedC = $false
} finally {
    $client.Close()
}

Log-Output "Result: TCP Connection Established = $connectedC"

if (-not $connectedC) {
    Log-Output "ASSERTION PASSED: Host cannot reach vault-db port (Port is unmapped and internal to vault-net).`n" "Green"
} else {
    Log-Output "FAILED: test_c: Host connected to vault port 5433! Vault must not be published.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (d): Recovery Service -> Vault Database (MUST SUCCEED)
# -------------------------------------------------------------------------
Log-Output "[Test D] Recovery Service to Vault Database (vault-db:5432)" "Yellow"
$cmdD = 'docker exec aegismem-recovery python -c "import socket; s = socket.socket(); s.settimeout(3); s.connect((\"vault-db\", 5432)); print(\"CONNECTED_OK\")" 2>&1'
Log-Output "Command: $cmdD"
$outD = & cmd.exe /c $cmdD
$exitD = $LASTEXITCODE
Log-Output "Result (Exit Code $exitD):`n$($outD -join "`n")"

if ($exitD -eq 0 -and ($outD -like "*CONNECTED_OK*")) {
    Log-Output "ASSERTION PASSED: Recovery service successfully connected to vault-db via vault-net.`n" "Green"
} else {
    Log-Output "FAILED: test_d: Recovery service failed to reach vault-db.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (e): Attacker container -> Public Gateway API (MUST SUCCEED)
# -------------------------------------------------------------------------
Log-Output "[Test E] Attacker container to Public Gateway API (http://aegismem-gateway:8000/health)" "Yellow"
$cmdE = 'docker exec aegismem-attacker curl -s -f http://aegismem-gateway:8000/health 2>&1'
Log-Output "Command: $cmdE"
$outE = & cmd.exe /c $cmdE
$exitE = $LASTEXITCODE
Log-Output "Result (Exit Code $exitE):`n$($outE -join "`n")"

if ($exitE -eq 0 -and ($outE -like "*healthy*")) {
    Log-Output "ASSERTION PASSED: Attacker successfully connected to Public Gateway API via public-net.`n" "Green"
} else {
    Log-Output "FAILED: test_e: Attacker could not connect to public gateway API.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Final Summary and Exit Status
# -------------------------------------------------------------------------
if ($allPassed) {
    Log-Output "=================================================================" "Green"
    Log-Output "PASSED: isolation: All 5 network-segmented assertions verified." "Green"
    Log-Output "Transcript saved to: $transcriptPath" "Green"
    Log-Output "=================================================================" "Green"
    exit 0
} else {
    Log-Output "=================================================================" "Red"
    Write-Host "FAILED: isolation: One or more network isolation assertions failed." -ForegroundColor Red
    Log-Output "=================================================================" "Red"
    exit 1
}
