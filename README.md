# AegisMem: Self-Healing Persistent Memory Security for Enterprise AI Customer Support

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.142.2-green.svg)](https://fastapi.tiangolo.com/)
[![Tests Passing](https://img.shields.io/badge/tests-239%20passed-brightgreen.svg)](tests/)
[![License: Research](https://img.shields.io/badge/license-Research-orange.svg)](LICENSE)

AegisMem is a self-healing security framework designed to protect the persistent, versioned long-term memory of enterprise AI agents. Instantiated for **Enterprise AI Customer Support**, AegisMem guards mission-critical enterprise knowledge (refund policies, warranty terms, escalation protocols, and pricing rules) against unauthorized tampering, adversarial memory poisoning, and historical state rewrites.

---

## Key Security Innovations

1. **Cryptographic Authority Tiers**:
   * **Tier 1: Signed Enterprise Policies** (Refunds, SLAs, escalation): Require staff Ed25519 digital signatures, SHA-256 hash chains, and single-use cryptographic nonces.
   * **Tier 2: Conversation-Derived Memories** (Customer claims, notes): Low authority, strictly sandboxed. Cannot override, alter, or merge into signed policy classes.
2. **TCRP (Trust-Cascaded Recovery Planning)**:
   * Traces semantic and temporal dependency graphs to quantify downstream contamination cascades.
   * Executes cost-optimized, feasibility-constrained remediation decisions (`RETAIN`, `ROLLBACK`, `QUARANTINE`).
3. **Multi-Domain Replicated Cryptographic Trust Vault**:
   * Solves the single-database rollback vulnerability ($k=1$ store corruption).
   * Maintains isolated out-of-band snapshots (`security/trust_vault/`) anchored by independent witness signatures.
   * Auto-repairs corrupted SQLite/PostgreSQL historical versions prior to rollback.
4. **Read-Path Verification Gate**:
   * Enforces zero-trust retrieval: the agent is never served memory content that fails signature, hash chain, or anchor validation.
   * Bounds exposure windows independently of asynchronous background detection latency.

---

## System Architecture

```
                                      +--------------------------+
                                      | Enterprise Administrator |
                                      +-------------+------------+
                                                    | (Signs with Ed25519)
                                                    v
+------------------+   Read Policy    +-------------+------------+    Replicates    +-----------------------+
|  Customer / LLM  | <============== |     AegisMem Gateway      | =============> | ReplicatedTrustVault  |
|  Support Agent   | (Read-Path Gate)|   (api/main.py, Port 8000)|  (Signed Snap) | (security/trust_vault)|
+------------------+                  +-------------+------------+                  +-----------------------+
                                                    |
                                         Outbox / Watcher Stream
                                                    v
                                      +-------------+------------+
                                      |  AegisMem Security Watcher|
                                      +-------------+------------+
                                                    | (Compromise Detected)
                                                    v
+------------------+                  +-------------+------------+
| SQLite / Postgres| <-------------- |   TCRP Recovery Engine    |
|   (Memory DB)    | (Auto-Repair &  |  - Dependency Impact      |
+------------------+    Rollback)     |  - Cost-Based Selection   |
                                      +--------------------------+
```

---

## Directory Structure

```text
├── api/                       # FastAPI Gateway & sensitive route controllers
├── core/
│   ├── detection/             # Multi-heuristic compromise detector
│   ├── graph/                 # NetworkX dependency graph & impact analyzer
│   ├── integrity/             # SHA-256 hash chains & Ed25519 manifest stores
│   ├── memory/                # SQLAlchemy models & repository abstractions
│   ├── provenance/            # Checkpoint stores & trusted head tracking
│   ├── recovery/              # TCRP planner, resolver, executor, & trust vault
│   ├── security/              # Session management, nonces, & owner approval
│   └── soc/                   # SOC audit logging, severity scoring, & alerts
├── data/                      # Persistent SQLite storage (data/aegismem.db)
├── frontend/                  # React + Vite Enterprise SOC Dashboard
├── security/
│   ├── keys/                  # Public keys and anchor credentials
│   ├── integrity_manifests/   # Canonical signed revision manifests
│   └── trust_vault/           # Replicated out-of-band cryptographic snapshots
├── tests/                     # 239+ automated security and recovery tests
├── Dockerfile                 # Production backend container definition
├── requirements.txt           # Pinned dependency manifest
└── README.md
```

---

## Quickstart & Verification

### Prerequisites
* Python 3.12 or 3.13
* Node.js 18+ (for frontend dashboard)

### 1. Environment Setup
```powershell
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite
AegisMem includes an extensive suite covering authorization, coordinated tampering, dependency propagation, multi-store vault resilience, and TCRP self-healing:
```powershell
pytest tests -v
```
*Current test status: 239 passed, 0 failures.*

### 3. Start the Backend Gateway
```powershell
uvicorn api.main:app --host 127.0.0.1 --port 8000
```
Interactive OpenAPI documentation will be accessible at `http://127.0.0.1:8000/docs`.

### 4. Launch the Enterprise SOC Dashboard
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. The dashboard provides:
* **Overview**: Real-time memory integrity gauges and TCRP protection pipeline status.
* **AI Assistant**: Secure customer support RAG assistant verified against the read-path gate.
* **Memory Management**: Monitored enterprise memory repository and dependency graph.
* **Live Recovery**: Visual 3-stage diffing (Trusted v1 $\rightarrow$ Attacked v2 $\rightarrow$ Recovered v3).
* **SOC Audit**: Telemetry tracking IP origin, session tokens, and threat severity.

---

## Security Model & Claims

| Attack Scenario | Vulnerability Without AegisMem | AegisMem Mitigation |
|---|---|---|
| **Direct Policy Tampering** (e.g. refund window 30 $\rightarrow$ 180 days) | Bot serves modified policy; direct financial loss | Watcher detects hash mismatch; read-path gate blocks access; TCRP rolls back to verified version. |
| **Historical Store Tampering** ($k=1$ attack on SQLite) | Single-store resolvers fail or quarantine permanently | TCRP falls back to `ReplicatedTrustVault`, verifies Ed25519 signature, and auto-repairs SQLite. |
| **Conversational Injection** (Customer talks agent into storing "policy") | Agent adopts customer claim as company rule | Memory class authority tiers prevent conversation notes from writing to policy classes. |
| **Total Multi-Store Compromise** ($k=n$) | Undetected corruption served to customers | All unverified candidates fail Ed25519 validation; system safely quarantines memory (0% forged data served). |

---

## Containerized Deployment (Docker)

To run the standalone backend container:
```bash
docker build -t aegismem-backend .
docker run -p 8000:8000 -v $(pwd)/data:/app/data aegismem-backend
```
