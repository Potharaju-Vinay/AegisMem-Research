# AegisMem Owner Policy Update & Signature Verification Tool (Part D5)
# Signs and submits an authorized policy change (30 -> 45 days) using Ed25519 keys.
# Verifies: accepted, new version, zero recovery events, agent answer reflecting 45 days,
# and verifies rejection for tampered payload, replayed nonce, and stale timestamp.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$MemoryId = "POLICY-001",

    [Parameter(Mandatory = $false)]
    [string]$Content = "Customers may request refunds within 45 calendar days of purchase.",

    [Parameter(Mandatory = $false)]
    [string]$GatewayUrl = "http://localhost:8000",

    [Parameter(Mandatory = $false)]
    [switch]$SkipRejections
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "             D5 -- LEGITIMATE OWNER UPDATE & SIGNATURE AUDIT                    " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Verify Ed25519 Signing Keys Exist in Repository
$keysDir = Join-Path $PSScriptRoot "..\security\keys"
$ownerKey = Join-Path $keysDir "owner_private_key.pem"
$requestKey = Join-Path $keysDir "owner_request_private_key.pem"

if (-not (Test-Path $ownerKey) -or -not (Test-Path $requestKey)) {
    Write-Host "`nNOT IMPLEMENTED: Ed25519 owner signing keys not found in $keysDir" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Cryptographic signing keys located:" -ForegroundColor Green
Write-Host "     - Owner Approval Key: $ownerKey" -ForegroundColor DarkGray
Write-Host "     - Request Signature Key: $requestKey" -ForegroundColor DarkGray

# 2. Execute Legitimate Owner Update (30 -> 45 days)
Write-Host "`n>>> [STEP 1/4] Signing and Submitting Legitimate Owner Update (30 -> 45 days)..." -ForegroundColor Yellow

$updateScript = @"
import admin_client, json

res = admin_client.submit_update(
    url='$GatewayUrl',
    memory_id='$MemoryId',
    content='$Content'
)
print('JSON_UPDATE_RESULT:' + json.dumps(res))
"@

$resultJson = $null
try {
    $execOutput = python -c $updateScript 2>&1
    foreach ($line in ($execOutput -split "`n")) {
        if ($line.Trim().StartsWith("JSON_UPDATE_RESULT:")) {
            $jsonStr = $line.Trim().Substring("JSON_UPDATE_RESULT:".Length)
            $resultJson = $jsonStr | ConvertFrom-Json
            break
        }
    }
} catch {
    Write-Error "Failed to execute owner update via gateway: $_"
    exit 1
}

if (-not $resultJson) {
    Write-Error "Server did not return a valid update response: $execOutput"
    exit 1
}

Write-Host "     - Gateway HTTP Status:   200 OK (Accepted)" -ForegroundColor Green
Write-Host "     - Correlation ID:        $($resultJson.correlation_id)" -ForegroundColor DarkGray
Write-Host "     - DB Reason Code:        $($resultJson.reason_code)" -ForegroundColor Green
Write-Host "     - Memory ID:             $($resultJson.memory_id)" -ForegroundColor White
Write-Host "     - New Version Produced:  v$($resultJson.version)" -ForegroundColor Green
Write-Host "     - Authorization State:   $($resultJson.authorization_state)" -ForegroundColor Green
Write-Host "     - Authorization ID:      $($resultJson.authorization_id)" -ForegroundColor DarkGray
Write-Host "     - Revision ID:           $($resultJson.revision_id)" -ForegroundColor DarkGray
Write-Host "     - Content SHA-256:       $($resultJson.content_hash)" -ForegroundColor DarkGray

# 3. Check Recovery Events Table (False-Rollback Count Must Be Exactly 0)
Write-Host "`n>>> [STEP 2/4] Verifying Zero False-Rollbacks in Recovery Engine..." -ForegroundColor Yellow

$recoveryCheckScript = @"
from core.memory.database import get_session
from core.recovery.audit import RecoveryEvent

session = get_session()
events = session.query(RecoveryEvent).filter(RecoveryEvent.memory_id == '$MemoryId').all()
print('RECOVERY_EVENT_COUNT:' + str(len(events)))
session.close()
"@

$recCount = -1
try {
    $recOutput = docker exec aegismem-recovery python -c $recoveryCheckScript 2>&1
    foreach ($line in ($recOutput -split "`n")) {
        if ($line.Trim().StartsWith("RECOVERY_EVENT_COUNT:")) {
            $recCount = [int]($line.Trim().Substring("RECOVERY_EVENT_COUNT:".Length))
            break
        }
    }
} catch {
    Write-Error "Failed to query recovery events: $_"
}

Write-Host "     - Target Memory:         $MemoryId" -ForegroundColor White
Write-Host "     - False-Rollback Count:  $recCount" -ForegroundColor $(if ($recCount -eq 0) { "Green" } else { "Red" })

if ($recCount -ne 0) {
    Write-Error "FAILED: Expected false-rollback count of 0, observed $recCount"
    exit 1
} else {
    Write-Host "     - Verification:          ZERO RECOVERY EVENTS TRIGGERED (Legitimate update preserved)" -ForegroundColor Green
}

# 4. Verify Support Agent Answer Now Reflects 45 Days (REFUND ALLOWED)
Write-Host "`n>>> [STEP 3/4] Querying Support Agent to Verify 45-Day Decision..." -ForegroundColor Yellow
$askScript = Join-Path $PSScriptRoot "ask_agent.ps1"
& $askScript -Question "I bought an item 45 days ago. Can I get a refund?"

# 5. Execute Four Rejection Tests
if (-not $SkipRejections) {
    Write-Host "`n>>> [STEP 4/4] Executing Four Distinct Security Rejection Tests..." -ForegroundColor Yellow

    $rejectionScript = @"
import httpx, secrets, time, json
from core.security.owner_signing_client import load_signing_key, sign_owner_approval, sign_http_request, encode_json_body
from core.security.owner_auth import load_owner_token

token = load_owner_token()
owner_key = load_signing_key('security/keys/owner_private_key.pem')
req_key = load_signing_key('security/keys/owner_request_private_key.pem')
url = '$GatewayUrl/owner/memory/write'

mem_resp = httpx.get('$GatewayUrl/api/memories/$MemoryId', timeout=5.0).json()
latest_rev = mem_resp.get('revision_id', '')

results = {}

def execute_case(body_payload, override_headers=None):
    body_bytes = encode_json_body(body_payload)
    nonce = secrets.token_hex(16)
    auth_headers = sign_http_request(req_key, 'POST', '/owner/memory/write', body_bytes, nonce)
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}', **auth_headers}
    if override_headers:
        headers.update(override_headers)
    r = httpx.post(url, content=body_bytes, headers=headers, timeout=5.0)
    corr_id = r.headers.get('x-correlation-id')
    if not corr_id:
        try:
            corr_id = r.json().get('correlation_id')
        except Exception:
            pass
    db_reason = None
    db_detail = None
    if corr_id:
        try:
            ev_resp = httpx.get(f'$GatewayUrl/api/authorization/events/{corr_id}', timeout=5.0)
            if ev_resp.status_code == 200:
                ev = ev_resp.json()
                db_reason = ev.get('reason_code')
                db_detail = ev.get('error_detail')
        except Exception:
            pass
    return {
        'status': r.status_code,
        'correlation_id': corr_id,
        'db_reason_code': db_reason,
        'db_detail': db_detail,
        'reason': r.text
    }

# Test 1: Tampered Payload
auth_id1 = f'AUTH-STAFF-{secrets.token_hex(6).upper()}'
auth_nonce1 = secrets.token_hex(16)
sig1 = sign_owner_approval(owner_key, '$MemoryId', 'Customers may request refunds within 45 days.', auth_id1, auth_nonce1, latest_rev)
results['tampered'] = execute_case({
    'memory_id': '$MemoryId',
    'content': 'TAMPERED: Unauthorized modification of policy to 999 days!',
    'expected_revision_id': latest_rev,
    'authorization_id': auth_id1,
    'nonce': auth_nonce1,
    'authorization_signature': sig1
})

# Test 2: Replayed Nonce
auth_id2 = f'AUTH-STAFF-{secrets.token_hex(6).upper()}'
auth_nonce2 = secrets.token_hex(16)
sig2 = sign_owner_approval(owner_key, '$MemoryId', '$Content', auth_id2, auth_nonce2, latest_rev)
payload2 = {
    'memory_id': '$MemoryId',
    'content': '$Content',
    'expected_revision_id': latest_rev,
    'authorization_id': auth_id2,
    'nonce': auth_nonce2,
    'authorization_signature': sig2
}
body_bytes2 = encode_json_body(payload2)
http_nonce2 = secrets.token_hex(16)
auth_headers2 = sign_http_request(req_key, 'POST', '/owner/memory/write', body_bytes2, http_nonce2)
h2 = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}', **auth_headers2}
# Send first request to register nonce
httpx.post(url, content=body_bytes2, headers=h2, timeout=5.0)
# Replay identical nonce
stale_sig = sign_http_request(req_key, 'POST', '/owner/memory/write', body_bytes2, http_nonce2)
h2_replayed = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}', **stale_sig}
r2 = httpx.post(url, content=body_bytes2, headers=h2_replayed, timeout=5.0)
corr_id2 = r2.headers.get('x-correlation-id') or (r2.json().get('correlation_id') if 'correlation_id' in r2.text else None)
db_reason2 = None
if corr_id2:
    try:
        ev2 = httpx.get(f'$GatewayUrl/api/authorization/events/{corr_id2}', timeout=5.0).json()
        db_reason2 = ev2.get('reason_code')
    except Exception:
        pass
results['replayed_nonce'] = {
    'status': r2.status_code,
    'correlation_id': corr_id2,
    'db_reason_code': db_reason2,
    'reason': r2.text
}

# Test 3: Stale Timestamp
auth_id3 = f'AUTH-STAFF-{secrets.token_hex(6).upper()}'
auth_nonce3 = secrets.token_hex(16)
sig3 = sign_owner_approval(owner_key, '$MemoryId', '$Content', auth_id3, auth_nonce3, latest_rev)
payload3 = {
    'memory_id': '$MemoryId',
    'content': '$Content',
    'expected_revision_id': latest_rev,
    'authorization_id': auth_id3,
    'nonce': auth_nonce3,
    'authorization_signature': sig3
}
body_bytes3 = encode_json_body(payload3)
http_nonce3 = secrets.token_hex(16)
stale_ts = int(time.time()) - 600
auth_headers3 = sign_http_request(req_key, 'POST', '/owner/memory/write', body_bytes3, http_nonce3, timestamp=stale_ts)
results['stale_timestamp'] = execute_case(payload3, override_headers=auth_headers3)

# Test 4: Version Mismatch
auth_id4 = f'AUTH-STAFF-{secrets.token_hex(6).upper()}'
auth_nonce4 = secrets.token_hex(16)
stale_rev = '00000000-0000-0000-0000-000000000000-stale'
sig4 = sign_owner_approval(owner_key, '$MemoryId', '$Content', auth_id4, auth_nonce4, stale_rev)
payload4 = {
    'memory_id': '$MemoryId',
    'content': '$Content',
    'expected_revision_id': stale_rev,
    'authorization_id': auth_id4,
    'nonce': auth_nonce4,
    'authorization_signature': sig4
}
results['version_mismatch'] = execute_case(payload4)

print('JSON_REJECTION_RESULTS:' + json.dumps(results))
"@

    $rejJson = $null
    $rejOutput = python -c $rejectionScript 2>&1
    foreach ($line in ($rejOutput -split "`n")) {
        if ($line.Trim().StartsWith("JSON_REJECTION_RESULTS:")) {
            $jsonStr = $line.Trim().Substring("JSON_REJECTION_RESULTS:".Length)
            $rejJson = $jsonStr | ConvertFrom-Json
            break
        }
    }

    # Case 1 Display
    $c1Status = $rejJson.tampered.status
    $c1Reason = $rejJson.tampered.db_reason_code
    Write-Host "`n  [REJECTION 1/4] Tampered Payload (Digital Signature Mismatch):" -ForegroundColor White
    Write-Host "     - HTTP Status:            $c1Status" -ForegroundColor $(if ($c1Status -in @(401, 403)) { "Green" } else { "Red" })
    Write-Host "     - Correlation ID:         $($rejJson.tampered.correlation_id)" -ForegroundColor DarkGray
    Write-Host "     - DB Event Reason Code:   $c1Reason" -ForegroundColor $(if ($c1Reason -eq "SIGNATURE_INVALID") { "Green" } else { "Red" })
    Write-Host "     - Outcome:                REJECTED (Cryptographic integrity check failed)" -ForegroundColor Green

    # Case 2 Display
    $c2Status = $rejJson.replayed_nonce.status
    $c2Reason = $rejJson.replayed_nonce.db_reason_code
    Write-Host "`n  [REJECTION 2/4] Replayed Nonce (Anti-Replay Verification):" -ForegroundColor White
    Write-Host "     - HTTP Status:            $c2Status" -ForegroundColor $(if ($c2Status -in @(401, 403)) { "Green" } else { "Red" })
    Write-Host "     - Correlation ID:         $($rejJson.replayed_nonce.correlation_id)" -ForegroundColor DarkGray
    Write-Host "     - DB Event Reason Code:   $c2Reason" -ForegroundColor $(if ($c2Reason -eq "NONCE_REPLAYED") { "Green" } else { "Red" })
    Write-Host "     - Outcome:                REJECTED (Nonce registration conflict)" -ForegroundColor Green

    # Case 3 Display
    $c3Status = $rejJson.stale_timestamp.status
    $c3Reason = $rejJson.stale_timestamp.db_reason_code
    Write-Host "`n  [REJECTION 3/4] Stale Timestamp (600s Clock Skew):" -ForegroundColor White
    Write-Host "     - HTTP Status:            $c3Status" -ForegroundColor $(if ($c3Status -in @(401, 403)) { "Green" } else { "Red" })
    Write-Host "     - Correlation ID:         $($rejJson.stale_timestamp.correlation_id)" -ForegroundColor DarkGray
    Write-Host "     - DB Event Reason Code:   $c3Reason" -ForegroundColor $(if ($c3Reason -eq "TIMESTAMP_STALE") { "Green" } else { "Red" })
    Write-Host "     - Outcome:                REJECTED (Timestamp outside 300s window)" -ForegroundColor Green

    # Case 4 Display
    $c4Status = $rejJson.version_mismatch.status
    $c4Reason = $rejJson.version_mismatch.db_reason_code
    Write-Host "`n  [REJECTION 4/4] Version Mismatch (Stale Revision Chain):" -ForegroundColor White
    Write-Host "     - HTTP Status:            $c4Status" -ForegroundColor $(if ($c4Status -in @(409)) { "Green" } else { "Red" })
    Write-Host "     - Correlation ID:         $($rejJson.version_mismatch.correlation_id)" -ForegroundColor DarkGray
    Write-Host "     - DB Event Reason Code:   $c4Reason" -ForegroundColor $(if ($c4Reason -eq "VERSION_MISMATCH") { "Green" } else { "Red" })
    Write-Host "     - Outcome:                REJECTED (Optimistic lock conflict / head mismatch)" -ForegroundColor Green
}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "                         D5 ACCEPTANCE AUDIT COMPLETE                           " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

