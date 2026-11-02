# AegisMem: Self-Healing Persistent Memory Security for Enterprise AI Customer Support

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.142.2-green.svg)](https://fastapi.tiangolo.com/)
[![Tests Passing](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![License: Research](https://img.shields.io/badge/license-Research-orange.svg)](LICENSE)

AegisMem is a self-healing security framework designed to protect the persistent, versioned long-term memory of enterprise AI agents. Instantiated for **Enterprise AI Customer Support**, AegisMem guards mission-critical enterprise knowledge (refund policies, warranty terms, escalation protocols, and access credentials) against unauthorized SQL tampering, adversarial memory poisoning, and historical state rewrites.

---

## Key Security Innovations

1. **Cryptographic Authority Tiers & Owner Authorization**:
   * **Tier 1: Signed Enterprise Policies** (Refunds, SLAs, escalation): Require enterprise owner Ed25519 digital signatures, canonical request signing, SHA-256 content hashes, and single-use cryptographic nonces.
   * **Tier 2: Conversation-Derived Memories** (Customer claims, notes): Low authority, sandboxed. Cannot override, alter, or merge into signed policy classes.
2. **TCRP (Trust-Cascaded Recovery Planning)**:
   * Traces semantic and temporal dependency graphs to quantify downstream contamination cascades.
   * Executes cost-optimized remediation decisions (`RETAIN`, `ROLLBACK`, `QUARANTINE`).
3. **Multi-Domain Replicated Cryptographic Trust Vault**:
   * Solves the single-database rollback vulnerability ($k=1$ store corruption).
   * Replicates out-of-band snapshots to an isolated database (`vault-db`) on an internal bridge (`vault-net`), validated against independent anchor witness signatures.
   * Auto-repairs corrupted primary database historical records prior to rollback.
4. **Read-Path Verification Gate**:
   * Enforces zero-trust retrieval: the agent is never served memory content that fails signature, hash chain, or anchor validation.
   * Bounds customer financial exposure independently of background watcher detection latency.

---

## System Architecture

```
                                      +--------------------------+
                                      | Enterprise Administrator |
                                      +-------------+------------+
                                                    | (Signs with Ed25519)
                                                    v
+------------------+   Read Policy    +-------------+------------+    Replicates    +-----------------------+
|  Support Agent   | <============== |     AegisMem Gateway      | =============> | ReplicatedTrustVault  |
|  (Port 8002)     | (ReadPathGate)  |   (Port 8000, Gateway)    |  (Signed Snap) | (vault-db, vault-net) |
+------------------+                  +-------------+------------+                  +-----------------------+
                                                    |                                           |
                                         PostgreSQL Change Hooks                                |
                                                    v                                           v
+------------------+                  +-------------+------------+                  +-----------------------+
|  memory-db       | <--------------- |    AegisMem Detector      |                  |   aegismem-recovery   |
|  (Port 5432)     |                  | (Background Watcher)     |                  | (TCRP Planner/Executor|
+------------------+                  +--------------------------+                  +-----------------------+
                                                                                                ^
                                                                                                | Counter-signs
                                                                                    +-----------------------+
                                                                                    |   anchor-witness      |
                                                                                    | (Independent Witness) |
                                                                                    +-----------------------+
```

### Containerized Multi-Service Deployment (`docker-compose.yml`)

The production deployment consists of 9 distinct containerized services with hardened network segmentation:

| Container Service | Role & Responsibility | Network Segment | Host Port | Secret Ownership |
| :--- | :--- | :--- | :---: | :--- |
| `aegismem-gateway` | Public FastAPI gateway, ReadPathGate, owner ingress | `data-net`, `anchor-net`, `public-net` | `127.0.0.1:8000` | Public keys only; zero private keys |
| `aegismem-detector` | Event-driven watcher detecting compromise in `memory-db` | `data-net` | None | None |
| `aegismem-recovery` | TCRP planner, resolver, executor, vault snapshot restorer | `vault-net`, `data-net` | None | Recovery private key + vault credentials |
| `anchor` | Independent witness signing service & checkpoint verifier | `anchor-net` | None | Anchor private signing key |
| `support-agent` | Enterprise AI support agent (RAG retrieval via Gateway) | `data-net` | `127.0.0.1:8002` | None |
| `memory-db` | Primary PostgreSQL database storing persistent memories | `data-net`, `public-net` | `127.0.0.1:5432` | Primary database credentials |
| `vault-db` | Isolated PostgreSQL Trust Vault for out-of-band snapshots | `vault-net` (internal) | None | Vault database credentials |
| `dashboard` | React/Vite Reviewer Dashboard & API proxy server | `public-net` | `127.0.0.1:5173` | None |
| `attacker` | Debian container simulating external and network threats | `public-net` | None | Attacker tools preinstalled |

---

## Quickstart & Verification on Windows

### Prerequisites
* Windows 10/11 with PowerShell 5.1+ or PowerShell Core 7+
* Python 3.12 or 3.13 installed
* Docker Desktop for Windows running with WSL2 backend

### 1. Environment Setup
```powershell
# Clone the repository
git clone https://github.com/Potharaju-Vinay/AegisMem-Research.git
cd AegisMem-Research

# Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite
Run the full test suite covering cryptographic signatures, nonce replay protection, multi-store vault resilience, and TCRP self-healing:
```powershell
pytest tests -q
```

### 3. Start Multi-Container Environment
Launch the 9-service hardened deployment:
```powershell
docker compose up -d --build
```
Verify container health:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/preflight.ps1
```

### 4. Step-by-Step Demonstration Script
Execute the reviewer demonstration workflow in Windows PowerShell:

1. **Verify Network-Segmented Isolation:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/prove_isolation.ps1
   ```
2. **Deterministic Baseline Seeding:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
   ```
3. **Query Support Agent (Day-45 Refund):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/ask_agent.ps1 -Question "I bought an item 45 days ago. Can I get a refund?"
   ```
   *Expected:* `REFUND DENIED` (under enterprise 30-day policy).
4. **Legitimate Owner Policy Update (Extend to 45 Days):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/owner_update.ps1
   ```
   *Expected:* Update accepted; false-rollback count = 0; agent now answers `REFUND ALLOWED`.
5. **Demonstrate Harm with Protection OFF (Negative Control):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
   powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Protection off
   ```
   *Expected:* Agent answers `REFUND ALLOWED` on unauthorized modification; measured customer exposure $\ge 1$.
6. **Full Autonomous Self-Healing Chain (Protection ON):**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
   powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Mode autonomous -Protection on
   ```
   *Expected:* Watcher detects tamper, TCRP restores verified version, ReadPathGate blocks unverified reads (0 wrong answers served), post-recovery answer is `REFUND DENIED`.

### 5. Run Evaluation Benchmarks ($N=200$ Trials)
To reproduce the full statistical evaluation across 5 memories $\times$ 4 defense stacks $\times$ 3 attack vectors:
```powershell
python scripts/run_evaluation_benchmarks.py --trials 10
```
Generates CSVs, JSON statistics, and PNG figures in `demo_runs/evaluation/`.

### 6. Reviewer Dashboard
Open `http://127.0.0.1:5173/` in your browser to inspect real-time container health, persistent memory version history (v1 $\rightarrow$ v2 $\rightarrow$ v3), and live SOC incident audit records.

---

## Disclosed Limitations & Scope Boundaries

To maintain scientific rigor, AegisMem explicitly bounds its operational claims:
1. **Network Segmentation vs. Physical Air-Gap:** Isolation between `memory-db` and `vault-db` is enforced via Docker bridge networking (`vault-net` internal bridge without host port mappings), not physical galvanic isolation or optical data diodes.
2. **Local Multi-Service Consensus:** Witness verification runs across local container processes (`anchor`, `aegismem-recovery`, `aegismem-gateway`). It is not a geographically distributed multi-datacenter Byzantine Fault Tolerant (BFT) Raft cluster.
3. **Host Key Isolation:** Cryptographic private keys are isolated via host filesystem mount restrictions and POSIX permissions, not hardware confidential computing enclaves (Intel SGX or AWS Nitro).
4. **Watcher Detection Mechanism:** Detection is driven by PostgreSQL database event change hooks and periodic background watcher polling (~500 ms loop), not kernel-level eBPF memory tracing.
5. **Measured Recovery Latency:** Self-healing recovery requires algorithmic dependency graph traversal and cryptographic validation. In our 50-trial autonomous benchmark, measured total recovery duration had a mean of 2,804.55 ms (median: 2,808.70 ms, p95: 3,694.13 ms); it is not sub-second.
