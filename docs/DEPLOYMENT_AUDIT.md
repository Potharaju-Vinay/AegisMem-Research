# AegisMem — Truth Audit and Deployment Report (D1)

**Date of Audit:** 2026-11-01  
**Auditor:** AegisMem Senior Security & Research Software Engineer  
**Target Environment:** Docker Compose on Windows (PowerShell)  
**Evaluator Scope:** PhD Reviewer Verification for Enterprise AI Customer Support  

---

## 1. Executive Summary

This audit assesses the physical runtime truth of the AegisMem Docker Compose deployment. In accordance with the project's scientific rigor guidelines:
* Every command, port, network, and health status has been inspected directly from disk and the live Docker runtime.
* No outputs, counts, or latency numbers are invented.
* Discrepancies between historical documentation claims and actual container configurations are explicitly identified.

---

## 2. Complete Service Audit Matrix

| Service Name | Container Name | Base Image | Real Command Executed | Networks | Published Ports | Health Status | Role: Real vs. Placeholder |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`memory-db`** | `aegismem-memory-db` | `postgres:16-alpine` | `postgres` (official entrypoint) | `data-net` | `0.0.0.0:5432->5432/tcp` | Healthy (`pg_isready`) | **Real Service** (Live PostgreSQL memory store) |
| **`vault-db`** | `aegismem-vault-db` | `postgres:16-alpine` | `postgres` (official entrypoint) | `vault-net` | `0.0.0.0:5433->5432/tcp` | Healthy (`pg_isready`) | **Real Service** (Trust Vault PostgreSQL store) |
| **`aegismem-gateway`** | `aegismem-gateway` | Custom (Python 3.12-slim) | `uvicorn api.main:app --host 0.0.0.0 --port 8000` | `public-net`, `data-net` | `0.0.0.0:8000->8000/tcp` | Healthy (`curl http://localhost:8000/health`) | **Real Service** (FastAPI Gateway, ReadPathGate, Auth, TCRP endpoints) |
| **`aegismem-detector`** | `aegismem-detector` | Custom (Python 3.12-slim) | `python -m core.security.watcher` | `data-net` | None | Running (healthcheck disabled) | **Real Service** (Continuous background watcher scanning memory table) |
| **`aegismem-recovery`** | `aegismem-recovery` | Custom (Python 3.12-slim) | `python -c "import time; print('AegisMem Self-Healing TCRP Resolver Active'); time.sleep(86400)"` | `data-net`, `vault-net` | None | Running (healthcheck disabled) | **Placeholder** (Background sleep process; active recovery runs inside gateway & watcher) |
| **`anchor`** | `aegismem-anchor-witness` | Custom (Python 3.12-slim) | `python -c "import time; print('AegisMem Independent Anchor Witness Active'); time.sleep(86400)"` | `anchor-net` | None | Running (healthcheck disabled) | **Placeholder** (Background sleep process; cryptographic anchor logic resides in `core.integrity.anchor`) |
| **`support-agent`** | `aegismem-support-agent` | Custom (Python 3.12-slim) | `python -c "import time; print('Enterprise Support Agent Active (RAG via ReadPathGate)'); time.sleep(86400)"` | `public-net` | None | Running (healthcheck disabled) | **Placeholder** (Background sleep process; RAG support agent logic is invoked via gateway `/chat` & Python SDK) |
| **`attacker`** | `aegismem-attacker` | `debian:bookworm-slim` | `bash -c "apt-get update && apt-get install -y curl jq python3 && echo 'Adversary Container Ready' && sleep infinity"` | `public-net` | None | Running | **Real Worker** (Debian container with curl, jq, python3; **NOT Kali**) |

---

## 3. Discrepancy Analysis

### Discrepancy 1: Attacker Image Identity
* **Claim in previous documentation:** The attacker was repeatedly called "Kali Linux".
* **Runtime Truth:** The attacker image is `debian:bookworm-slim`.
* **Remediation:** It must strictly be identified as the "Debian adversary container" or "network attacker", never "Kali".

### Discrepancy 2: Vault Database Network Exposure
* **Security Principle:** The trust vault is network-segmented and must never be exposed outside the internal `vault-net`.
* **Runtime Truth:** `vault-db` had `ports: - "5433:5432"` binding to `0.0.0.0:5433`, making the vault directly reachable from the host and external network.
* **Remediation:** Remove the `ports` directive entirely from `vault-db`.

### Discrepancy 3: Live Memory Database Exposure
* **Security Principle:** Live storage should only be accessible locally or through the internal Docker data network.
* **Runtime Truth:** `memory-db` was published to `0.0.0.0:5432`, exposing it on all external network interfaces of the host.
* **Remediation:** Change port binding to `127.0.0.1:5432:5432`.

### Discrepancy 4: Placeholder Services vs. Architectural Roles
* **Runtime Truth:** `aegismem-recovery`, `anchor`, and `support-agent` currently execute `time.sleep(86400)`.
* **Functional Location:** 
  - TCRP Recovery is orchestrated inside `api/main.py` and `core/security/watcher.py` (calling `TCRPResolver` and `ReplicatedTrustVault`).
  - Anchor verification is executed as library code in `core/integrity/anchor.py`.
  - The Support Agent query engine is served live by `api/main.py` (`EnterpriseAgent` and `ReadPathGate`).
* **Remediation:** Clearly document that these three containers represent simulated network boundaries/witnesses, while the operational logic runs inside `aegismem-gateway` and `aegismem-detector`.

### Discrepancy 5: Hardcoded Passwords in Compose File
* **Security Principle:** Passwords must not be plain-text hardcoded in version-controlled Compose definitions.
* **Runtime Truth:** Plaintext passwords (`aegis_secure_password_2026`, `vault_airgapped_password_2026`) were present in `docker-compose.yml`.
* **Remediation:** Externalize to `.env` variables (`AEGISMEM_DB_PASSWORD`, `AEGISMEM_VAULT_PASSWORD`) with appropriate local fallbacks.

### Discrepancy 6: Missing `.dockerignore`
* **Runtime Truth:** No `.dockerignore` existed, causing `.git`, `venv`, `node_modules`, and local cache files to be copied into container build contexts, bloating image layers and slowing builds.
* **Remediation:** Create `.dockerignore` excluding `venv`, `.git`, `node_modules`, `__pycache__`, `.env`, `*.db`, and scratch files.

---

## 4. Remediation Plan (D1 Actions)

1. **`docker-compose.yml` Hardening:**
   - Remove `ports` from `vault-db`.
   - Bind `memory-db` ports to `127.0.0.1:5432:5432`.
   - Reference passwords via environment variables.
   - Maintain escaped `$$` for hash strings.
2. **`.dockerignore` Creation:**
   - Add standard exclusions for Git, virtualenvs, temporary database files, node artifacts, and Python cache.
3. **Preflight Script (`scripts/preflight.ps1`):**
   - Query Docker Compose CLI dynamically (`docker compose ps --format json`).
   - Dynamically compute running service count (never hardcoded).
   - Verify health and network status.
   - Assert exit code 0 on success, non-zero on any missing/stopped service.

