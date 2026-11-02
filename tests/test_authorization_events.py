"""
Test Authorization Events and Multi-Case Update Suite (Task F6)

Requirements verified:
1. authorization_events table records distinct reason codes:
   ACCEPTED, SIGNATURE_INVALID, NONCE_REPLAYED, TIMESTAMP_STALE, VERSION_MISMATCH, KEY_UNKNOWN, INTERNAL_ERROR.
2. Anti-oracle protection: client gets only generic error message + X-Correlation-ID header.
3. Multi-case positive suite: >= 100 legitimate signed updates across 5 memories.
   Assert from recovery_events and detector that exactly 0 were rolled back.
4. Multi-case negative suite: >= 30 negative cases of each rejection type:
   - 30 x SIGNATURE_INVALID
   - 30 x NONCE_REPLAYED
   - 30 x TIMESTAMP_STALE
   - 30 x VERSION_MISMATCH
5. Negative control: broken signature verification path rejects 100% of attempts.
"""

import json
import secrets
import subprocess
import time
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx

import admin_client
from core.security.owner_signing_client import (
    encode_json_body,
    load_signing_key,
    sign_http_request,
    sign_owner_approval,
)

GATEWAY_URL = "http://127.0.0.1:8000"
MEMORIES = [
    "POLICY-001",
    "POLICY-002",
    "SOP-003",
    "ENT-ACCESS-001",
    "ENT-BACKUP-003",
]
OWNER_KEY_PATH = "security/keys/owner_private_key.pem"
REQ_KEY_PATH = "security/keys/owner_request_private_key.pem"


def query_db_sql(sql: str) -> list:
    """Executes SQL inside the authoritative recovery container against demo DB."""
    py_code = f"""
from core.memory.database import get_session
from sqlalchemy import text
import json
s = get_session()
res = s.execute(text({repr(sql)})).fetchall()
s.close()
print('SQL_RESULT:' + json.dumps([[str(col) for col in row] for row in res]))
"""
    cmd = ["docker", "exec", "aegismem-recovery", "python", "-c", py_code]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    for line in proc.stdout.splitlines():
        if line.startswith("SQL_RESULT:"):
            return json.loads(line[len("SQL_RESULT:"):])
    return []


def test_positive_100_legitimate_signed_updates():
    """
    Submits >= 100 legitimate signed updates across 5 different memories.
    Asserts zero false rollbacks in recovery_events, zero detector corruption alerts,
    and >= 100 ACCEPTED events in authorization_events.
    """
    print("\n" + "=" * 80)
    print(">>> [TEST F6-1] Running 100 Legitimate Signed Updates Across 5 Memories...")
    print("=" * 80)

    total_updates = 100
    owner_token = None
    from core.security.owner_auth import load_owner_token
    try:
        owner_token = load_owner_token()
    except Exception:
        pass

    accepted_count = 0
    start_time = time.time()

    for i in range(total_updates):
        mem_id = MEMORIES[i % len(MEMORIES)]
        new_content = f"Legitimate enterprise policy update batch #{i + 1} for {mem_id}. Validated."

        res = admin_client.submit_update(
            url=GATEWAY_URL,
            memory_id=mem_id,
            content=new_content,
            owner_token=owner_token,
        )

        assert res.get("reason_code") == "ACCEPTED", f"Update #{i+1} rejected: {res}"
        assert res.get("authorization_state") == "AUTHORIZED"
        assert res.get("correlation_id", "").startswith("auth-")
        accepted_count += 1

        if (i + 1) % 20 == 0 or (i + 1) == total_updates:
            print(f"  - Completed {i + 1}/{total_updates} legitimate updates (Memory: {mem_id}, Version: v{res.get('version')})")

    duration = time.time() - start_time
    print(f"[PASS] Successfully completed {accepted_count} legitimate updates in {duration:.2f}s.")

    # 1. Assert authorization_events table has >= 100 ACCEPTED records
    db_rows = query_db_sql("SELECT COUNT(*) FROM authorization_events WHERE reason_code = 'ACCEPTED'")
    accepted_in_db = int(db_rows[0][0])
    print(f"  - Verified authorization_events rows (reason_code='ACCEPTED'): {accepted_in_db}")
    assert accepted_in_db >= 100, f"Expected >= 100 ACCEPTED rows, found {accepted_in_db}"

    # 2. Assert recovery_events has exactly 0 false rollbacks
    rec_rows = query_db_sql("SELECT COUNT(*) FROM recovery_events")
    recovery_count = int(rec_rows[0][0])
    print(f"  - Verified recovery_events table count (false-rollbacks): {recovery_count}")
    assert recovery_count == 0, f"Expected 0 recovery events for legitimate updates, found {recovery_count}"

    # 3. Assert all memories remain active and untampered
    for mem_id in MEMORIES:
        resp = httpx.get(f"{GATEWAY_URL}/api/memories/{mem_id}", timeout=5.0).json()
        assert resp.get("status") == "active", f"Memory {mem_id} has non-active status: {resp.get('status')}"
        assert resp.get("trust_score") == 1.0, f"Memory {mem_id} trust score degraded: {resp.get('trust_score')}"
    print("  - Verified detector & read gate: 0 memories corrupted or quarantined.")


def test_negative_30_cases_per_rejection_type():
    """
    Submits >= 30 negative cases for each required rejection type:
    - 30 x SIGNATURE_INVALID
    - 30 x NONCE_REPLAYED
    - 30 x TIMESTAMP_STALE
    - 30 x VERSION_MISMATCH

    Verifies anti-oracle response protection and exact database reason codes.
    """
    print("\n" + "=" * 80)
    print(">>> [TEST F6-2] Running 30 Rejection Cases for Each Distinct Reason Code...")
    print("=" * 80)

    from core.security.owner_auth import load_owner_token
    token = load_owner_token()
    owner_key = load_signing_key(OWNER_KEY_PATH)
    req_key = load_signing_key(REQ_KEY_PATH)
    write_url = f"{GATEWAY_URL}/owner/memory/write"

    counts = {
        "SIGNATURE_INVALID": 0,
        "NONCE_REPLAYED": 0,
        "TIMESTAMP_STALE": 0,
        "VERSION_MISMATCH": 0,
    }

    n_trials = 30

    # 1. 30 x SIGNATURE_INVALID (Tampered payload)
    print(f"  [SUITE 1/4] Executing {n_trials} SIGNATURE_INVALID trials...")
    for i in range(n_trials):
        mem_id = MEMORIES[i % len(MEMORIES)]
        mem_info = httpx.get(f"{GATEWAY_URL}/api/memories/{mem_id}", timeout=5.0).json()
        rev_id = mem_info["revision_id"]

        auth_id = f"AUTH-TEST-{secrets.token_hex(6).upper()}"
        auth_nonce = secrets.token_hex(16)
        # Sign valid statement
        sig = sign_owner_approval(owner_key, mem_id, "Original valid policy text", auth_id, auth_nonce, rev_id)

        # Tamper payload text
        tampered_body = {
            "memory_id": mem_id,
            "content": f"TAMPERED UNAUTHORIZED CONTENT #{i+1}",
            "expected_revision_id": rev_id,
            "authorization_id": auth_id,
            "nonce": auth_nonce,
            "authorization_signature": sig,
        }
        raw_bytes = encode_json_body(tampered_body)
        http_nonce = secrets.token_hex(16)
        auth_h = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **auth_h}

        resp = httpx.post(write_url, content=raw_bytes, headers=headers, timeout=5.0)
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

        # Anti-oracle assertion: client gets generic error message only
        resp_data = resp.json()
        assert resp_data.get("detail") == "Authorization denied."
        corr_id = resp.headers.get("x-correlation-id") or resp_data.get("correlation_id")
        assert corr_id and corr_id.startswith("auth-")

        # Database audit assertion: exact reason code recorded
        ev_resp = httpx.get(f"{GATEWAY_URL}/api/authorization/events/{corr_id}", timeout=5.0).json()
        assert ev_resp.get("reason_code") == "SIGNATURE_INVALID", f"Expected SIGNATURE_INVALID, got {ev_resp.get('reason_code')}"
        counts["SIGNATURE_INVALID"] += 1

    print(f"  [PASS] 30/30 SIGNATURE_INVALID cases successfully audited.")

    # 2. 30 x NONCE_REPLAYED (Replay attack)
    print(f"  [SUITE 2/4] Executing {n_trials} NONCE_REPLAYED trials...")
    for i in range(n_trials):
        mem_id = MEMORIES[i % len(MEMORIES)]
        mem_info = httpx.get(f"{GATEWAY_URL}/api/memories/{mem_id}", timeout=5.0).json()
        rev_id = mem_info["revision_id"]

        auth_id = f"AUTH-TEST-{secrets.token_hex(6).upper()}"
        auth_nonce = secrets.token_hex(16)
        content = f"Anti-replay policy check #{i+1}"
        sig = sign_owner_approval(owner_key, mem_id, content, auth_id, auth_nonce, rev_id)

        body = {
            "memory_id": mem_id,
            "content": content,
            "expected_revision_id": rev_id,
            "authorization_id": auth_id,
            "nonce": auth_nonce,
            "authorization_signature": sig,
        }
        raw_bytes = encode_json_body(body)
        http_nonce = f"test-replay-nonce-{secrets.token_hex(12)}"
        auth_h = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **auth_h}

        # First request consumes nonce
        httpx.post(write_url, content=raw_bytes, headers=headers, timeout=5.0)

        # Replay request reuses identical nonce
        replayed_sig = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce)
        replayed_h = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **replayed_sig}
        resp = httpx.post(write_url, content=raw_bytes, headers=replayed_h, timeout=5.0)

        assert resp.status_code == 401, f"Expected 401 for replayed nonce, got {resp.status_code}"
        resp_data = resp.json()
        assert resp_data.get("detail") == "Authorization denied."
        corr_id = resp.headers.get("x-correlation-id") or resp_data.get("correlation_id")
        assert corr_id

        ev_resp = httpx.get(f"{GATEWAY_URL}/api/authorization/events/{corr_id}", timeout=5.0).json()
        assert ev_resp.get("reason_code") == "NONCE_REPLAYED", f"Expected NONCE_REPLAYED, got {ev_resp.get('reason_code')}"
        counts["NONCE_REPLAYED"] += 1

    print(f"  [PASS] 30/30 NONCE_REPLAYED cases successfully audited.")

    # 3. 30 x TIMESTAMP_STALE (Expired clock window)
    print(f"  [SUITE 3/4] Executing {n_trials} TIMESTAMP_STALE trials...")
    for i in range(n_trials):
        mem_id = MEMORIES[i % len(MEMORIES)]
        mem_info = httpx.get(f"{GATEWAY_URL}/api/memories/{mem_id}", timeout=5.0).json()
        rev_id = mem_info["revision_id"]

        auth_id = f"AUTH-TEST-{secrets.token_hex(6).upper()}"
        auth_nonce = secrets.token_hex(16)
        content = f"Stale timestamp test #{i+1}"
        sig = sign_owner_approval(owner_key, mem_id, content, auth_id, auth_nonce, rev_id)

        body = {
            "memory_id": mem_id,
            "content": content,
            "expected_revision_id": rev_id,
            "authorization_id": auth_id,
            "nonce": auth_nonce,
            "authorization_signature": sig,
        }
        raw_bytes = encode_json_body(body)
        http_nonce = secrets.token_hex(16)
        stale_time = int(time.time()) - (600 + i * 10)  # > 300s window
        auth_h = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce, timestamp=stale_time)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **auth_h}

        resp = httpx.post(write_url, content=raw_bytes, headers=headers, timeout=5.0)
        assert resp.status_code == 401, f"Expected 401 for stale timestamp, got {resp.status_code}"
        resp_data = resp.json()
        assert resp_data.get("detail") == "Authorization denied."
        corr_id = resp.headers.get("x-correlation-id") or resp_data.get("correlation_id")
        assert corr_id

        ev_resp = httpx.get(f"{GATEWAY_URL}/api/authorization/events/{corr_id}", timeout=5.0).json()
        assert ev_resp.get("reason_code") == "TIMESTAMP_STALE", f"Expected TIMESTAMP_STALE, got {ev_resp.get('reason_code')}"
        counts["TIMESTAMP_STALE"] += 1

    print(f"  [PASS] 30/30 TIMESTAMP_STALE cases successfully audited.")

    # 4. 30 x VERSION_MISMATCH (Stale revision chain)
    print(f"  [SUITE 4/4] Executing {n_trials} VERSION_MISMATCH trials...")
    for i in range(n_trials):
        mem_id = MEMORIES[i % len(MEMORIES)]
        stale_rev_id = f"00000000-0000-0000-0000-{secrets.token_hex(6)}"

        auth_id = f"AUTH-TEST-{secrets.token_hex(6).upper()}"
        auth_nonce = secrets.token_hex(16)
        content = f"Version mismatch test #{i+1}"
        sig = sign_owner_approval(owner_key, mem_id, content, auth_id, auth_nonce, stale_rev_id)

        body = {
            "memory_id": mem_id,
            "content": content,
            "expected_revision_id": stale_rev_id,
            "authorization_id": auth_id,
            "nonce": auth_nonce,
            "authorization_signature": sig,
        }
        raw_bytes = encode_json_body(body)
        http_nonce = secrets.token_hex(16)
        auth_h = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **auth_h}

        resp = httpx.post(write_url, content=raw_bytes, headers=headers, timeout=5.0)
        assert resp.status_code == 409, f"Expected 409 for version mismatch, got {resp.status_code}"
        resp_data = resp.json()
        assert resp_data.get("detail") == "Authorization denied."
        corr_id = resp.headers.get("x-correlation-id") or resp_data.get("correlation_id")
        assert corr_id

        ev_resp = httpx.get(f"{GATEWAY_URL}/api/authorization/events/{corr_id}", timeout=5.0).json()
        assert ev_resp.get("reason_code") == "VERSION_MISMATCH", f"Expected VERSION_MISMATCH, got {ev_resp.get('reason_code')}"
        counts["VERSION_MISMATCH"] += 1

    print(f"  [PASS] 30/30 VERSION_MISMATCH cases successfully audited.")

    # Direct DB assertion on row counts
    print("\n[POSTGRES READ-BACK OF REJECTION COUNTS]")
    for code, expected_min in counts.items():
        rows = query_db_sql(f"SELECT COUNT(*) FROM authorization_events WHERE reason_code = '{code}'")
        actual_count = int(rows[0][0])
        print(f"  - Database row count for {code:18}: {actual_count} (>= {expected_min})")
        assert actual_count >= expected_min


def test_negative_control_broken_signature_path():
    """
    Negative control: deliberately corrupts the cryptographic signature
    to prove that the test harness and gateway reliably reject invalid authorizations.
    Must fail 100% of attempted writes with SIGNATURE_INVALID and produce zero accepted updates.
    """
    print("\n" + "=" * 80)
    print(">>> [TEST F6-3] Running Negative Control (Deliberately Broken Signature)...")
    print("=" * 80)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.security.owner_auth import load_owner_token

    # Generate an untrusted rogue key not recognized by the trust anchor / gateway
    rogue_key = Ed25519PrivateKey.generate()
    req_key = load_signing_key(REQ_KEY_PATH)
    token = load_owner_token()
    write_url = f"{GATEWAY_URL}/owner/memory/write"

    rejected_failures = 0
    control_trials = 10

    for i in range(control_trials):
        mem_id = MEMORIES[i % len(MEMORIES)]
        mem_info = httpx.get(f"{GATEWAY_URL}/api/memories/{mem_id}", timeout=5.0).json()
        rev_id = mem_info["revision_id"]

        auth_id = f"AUTH-ROGUE-{secrets.token_hex(6).upper()}"
        auth_nonce = secrets.token_hex(16)
        content = f"Rogue unapproved policy update attempt #{i+1}"
        # Sign with rogue key
        sig = sign_owner_approval(rogue_key, mem_id, content, auth_id, auth_nonce, rev_id)

        body = {
            "memory_id": mem_id,
            "content": content,
            "expected_revision_id": rev_id,
            "authorization_id": auth_id,
            "nonce": auth_nonce,
            "authorization_signature": sig,
        }
        raw_bytes = encode_json_body(body)
        http_nonce = secrets.token_hex(16)
        auth_h = sign_http_request(req_key, "POST", "/owner/memory/write", raw_bytes, http_nonce)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", **auth_h}

        resp = httpx.post(write_url, content=raw_bytes, headers=headers, timeout=5.0)
        assert resp.status_code == 401
        corr_id = resp.headers.get("x-correlation-id") or resp.json().get("correlation_id")

        ev_resp = httpx.get(f"{GATEWAY_URL}/api/authorization/events/{corr_id}", timeout=5.0).json()
        assert ev_resp.get("reason_code") == "SIGNATURE_INVALID"
        rejected_failures += 1

    print(f"  [PASS] Negative control succeeded: 10/10 ({rejected_failures}/{control_trials}) unauthorized attempts rejected as SIGNATURE_INVALID.")


if __name__ == "__main__":
    print("=" * 80)
    print("Starting Task F6 Authorization & Multi-Case Update Suite")
    print("=" * 80)

    test_positive_100_legitimate_signed_updates()
    test_negative_30_cases_per_rejection_type()
    test_negative_control_broken_signature_path()

    print("\n" + "=" * 80)
    print("TASK F6 TEST SUITE COMPLETED: ALL ASSERTIONS AND NEGATIVE CONTROLS PASSED")
    print("=" * 80)
