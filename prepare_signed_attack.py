import json
import secrets
import time
from pathlib import Path
from core.security.owner_signing_client import load_signing_key, sign_http_request, encode_json_body

base = Path.cwd()
key = load_signing_key(base / "security" / "keys" / "owner_request_private_key.pem")
payload = {
    "memory_id": "PHASE3-TEST",
    "modified_content": "CONTROLLED TAMPERING TEST: refund policy changed to 180 days",
    "attacker": "kali-controlled-lab",
    "attack_type": "content_tampering"
}
body = encode_json_body(payload)
headers = sign_http_request(
    key,
    method="POST",
    path="/attacker/memory/write",
    body=body,
    nonce=secrets.token_hex(16),
    timestamp=int(time.time())
)
headers["Authorization"] = "Bearer " + __import__("os").environ.get("AEGISMEM_OWNER_TOKEN", "")
if not headers["Authorization"].endswith(" "):
    Path("signed_attack.json").write_text(
        json.dumps({"url": "http://192.168.56.1:8000/attacker/memory/write", "headers": headers, "body": payload}),
        encoding="utf-8"
    )
    print("Signed request saved locally.")
else:
    print("Owner token is not set in this PowerShell session. No request file created.")
