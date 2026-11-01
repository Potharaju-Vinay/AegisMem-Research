# scripts/prove_isolation.ps1
# AegisMem Network-Segmented Isolation Proof (D2 Enhanced)
# Executes real connection tests across network zones and asserts strict isolation boundaries
# Tests:
#   A: Attacker -> vault-db by hostname (Must fail)
#   B: Attacker -> anchor by hostname (Must fail)
#   C: Host -> vault-db port (Must fail)
#   D: Recovery -> vault-db by hostname (Must succeed)
#   E: Attacker -> Gateway API (Must succeed)
#   F: Attacker -> vault-db by Direct IP (Must fail)
#   G: Attacker -> anchor by Direct IP (Reports NOT IMPLEMENTED if placeholder)
#   H: Recovery -> vault-db by Direct IP (Must succeed)

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

# Dynamically query container IP addresses (zero hardcoding)
Log-Output "[Discovery] Dynamically querying runtime container network configurations..." "Yellow"

$vaultIp = (& cmd.exe /c 'docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" aegismem-vault-db').Trim()
$anchorIp = (& cmd.exe /c 'docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" aegismem-anchor-witness').Trim()
$attackerIp = (& cmd.exe /c 'docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" aegismem-attacker').Trim()
$recoveryNets = (& cmd.exe /c 'docker inspect -f "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}" aegismem-recovery').Trim()

Log-Output "  - vault-db IP    : $vaultIp (vault-net)"
Log-Output "  - anchor IP      : $anchorIp (anchor-net)"
Log-Output "  - attacker IP    : $attackerIp (public-net)"
Log-Output "  - recovery IPs   : $recoveryNets`n"

$allPassed = $true

# -------------------------------------------------------------------------
# Test (a): Attacker container -> Vault Database by Hostname (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test A] Attacker container to Vault Database by Hostname (vault-db:5432)" "Yellow"
$cmdA = 'docker exec aegismem-attacker python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect((\"vault-db\", 5432))" 2>&1'
Log-Output "Command: $cmdA"
$outA = & cmd.exe /c $cmdA
$exitA = $LASTEXITCODE
Log-Output "Result (Exit Code $exitA):`n$($outA -join "`n")"

if ($exitA -ne 0) {
    Log-Output "ASSERTION PASSED: Attacker cannot resolve or route to vault-db hostname.`n" "Green"
} else {
    Log-Output "FAILED: test_a: Attacker resolved and connected to vault-db! Isolation boundary breached.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (b): Attacker container -> Anchor Witness by Hostname (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test B] Attacker container to Anchor Witness by Hostname (anchor:8000)" "Yellow"
$cmdB = 'docker exec aegismem-attacker python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect((\"anchor\", 8000))" 2>&1'
Log-Output "Command: $cmdB"
$outB = & cmd.exe /c $cmdB
$exitB = $LASTEXITCODE
Log-Output "Result (Exit Code $exitB):`n$($outB -join "`n")"

if ($exitB -ne 0) {
    Log-Output "ASSERTION PASSED: Attacker cannot resolve or route to anchor hostname.`n" "Green"
} else {
    Log-Output "FAILED: test_b: Attacker resolved and connected to anchor! Isolation boundary breached.`n" "Red"
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
# Test (d): Recovery Service -> Vault Database by Hostname (MUST SUCCEED)
# -------------------------------------------------------------------------
Log-Output "[Test D] Recovery Service to Vault Database by Hostname (vault-db:5432)" "Yellow"
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
# Test (f): Attacker container -> Vault Database by Direct IP (MUST FAIL)
# -------------------------------------------------------------------------
Log-Output "[Test F] Attacker container to Vault Database by Direct IP ($($vaultIp):5432)" "Yellow"
$cmdF = "docker exec aegismem-attacker python3 -c ""import socket; s = socket.socket(); s.settimeout(3); s.connect(('$vaultIp', 5432))"" 2>&1"
Log-Output "Command: $cmdF"
Log-Output "Destination IP: $vaultIp, Port: 5432"
$outF = & cmd.exe /c $cmdF
$exitF = $LASTEXITCODE
Log-Output "Result (Exit Code $exitF):`n$($outF -join "`n")"

if ($exitF -ne 0) {
    Log-Output "ASSERTION PASSED: Direct IP TCP routing blocked between public-net attacker and vault-db (${vaultIp}:5432).`n" "Green"
} else {
    Log-Output "FAILED: test_f: Attacker established direct IP connection to vault-db (${vaultIp}:5432)! Inter-bridge routing leak detected.`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Test (g): Attacker container -> Anchor Witness by Direct IP (Inspect Listener)
# -------------------------------------------------------------------------
Log-Output "[Test G] Attacker container to Anchor Witness by Direct IP ($($anchorIp))" "Yellow"

# Query anchor container to determine if an active server daemon is listening
$anchorPortsRaw = (& cmd.exe /c 'docker exec aegismem-anchor-witness python -c "with open(\"/proc/net/tcp\") as f: print(len(f.readlines()) - 1)" 2>&1').Trim()
$anchorHasListener = $false
if ($anchorPortsRaw -match "^\d+$" -and [int]$anchorPortsRaw -gt 1) {
    $anchorHasListener = $true
}

if (-not $anchorHasListener) {
    Log-Output "Destination IP: $anchorIp"
    Log-Output "Anchor Service Status: Placeholder worker (time.sleep) - No active server daemon or listening port."
    Log-Output "NOT IMPLEMENTED: Anchor daemon listening port; direct IP port isolation test unavailable for this service.`n" "Yellow"
} else {
    $cmdG = "docker exec aegismem-attacker python3 -c ""import socket; s = socket.socket(); s.settimeout(3); s.connect(('$anchorIp', 8000))"" 2>&1"
    Log-Output "Command: $cmdG"
    $outG = & cmd.exe /c $cmdG
    $exitG = $LASTEXITCODE
    Log-Output "Result (Exit Code $exitG):`n$($outG -join "`n")"
    if ($exitG -ne 0) {
        Log-Output "ASSERTION PASSED: Direct IP connection to anchor failed as expected.`n" "Green"
    } else {
        Log-Output "FAILED: test_g: Attacker connected to anchor direct IP!`n" "Red"
        $allPassed = $false
    }
}

# -------------------------------------------------------------------------
# Test (h): Recovery Service -> Vault Database by Direct IP (MUST SUCCEED)
# -------------------------------------------------------------------------
Log-Output "[Test H] Recovery Service to Vault Database by Direct IP ($($vaultIp):5432)" "Yellow"
$cmdH = "docker exec aegismem-recovery python -c ""import socket; s = socket.socket(); s.settimeout(3); s.connect(('$vaultIp', 5432)); print('CONNECTED_DIRECT_IP_OK')"" 2>&1"
Log-Output "Command: $cmdH"
Log-Output "Destination IP: $vaultIp, Port: 5432"
$outH = & cmd.exe /c $cmdH
$exitH = $LASTEXITCODE
Log-Output "Result (Exit Code $exitH):`n$($outH -join "`n")"

if ($exitH -eq 0 -and ($outH -like "*CONNECTED_DIRECT_IP_OK*")) {
    Log-Output "ASSERTION PASSED: Recovery service connected to vault-db by Direct IP (${vaultIp}:5432) over vault-net.`n" "Green"
} else {
    Log-Output "FAILED: test_h: Recovery service failed to connect to vault-db by Direct IP (${vaultIp}:5432).`n" "Red"
    $allPassed = $false
}

# -------------------------------------------------------------------------
# Final Summary and Exit Status
# -------------------------------------------------------------------------
if ($allPassed) {
    Log-Output "=================================================================" "Green"
    Log-Output "PASSED: isolation: All active network-segmented assertions verified." "Green"
    Log-Output "Transcript saved to: $transcriptPath" "Green"
    Log-Output "=================================================================" "Green"
    exit 0
} else {
    Log-Output "=================================================================" "Red"
    Write-Host "FAILED: isolation: One or more network isolation assertions failed." -ForegroundColor Red
    Log-Output "=================================================================" "Red"
    exit 1
}
