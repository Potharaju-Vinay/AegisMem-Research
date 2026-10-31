# AegisMem: Self-Healing Persistent Memory Security for Enterprise AI Customer Support

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.142.2-green.svg)](https://fastapi.tiangolo.com/)
[![Tests Passing](https://img.shields.io/badge/tests-296%20passed-brightgreen.svg)](tests/)
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
pytest tests -q
```
*Current test status: 296 passed, 0 failures.*

### 3. One-Command End-to-End Enterprise Demo (Milestone M10)
Demonstrates the full 7-step enterprise lifecycle: signed staff update $\rightarrow$ mid-run database tampering $\rightarrow$ fail-closed read gate interception (0 wrong answers) $\rightarrow$ self-healing recovery from Trust Vault $\rightarrow$ restored correct answer $\rightarrow$ multi-format forensic incident export (JSON, Markdown, PDF):
```powershell
python scripts/demo_end_to_end.py
# Or via Makefile:
make demo
```

### 4. Reproducibility & Research Commands (`Makefile`)
```bash
make demo                        # End-to-end self-healing enterprise lifecycle walkthrough
make seed                        # Initialize synthetic policies, FAQs, graph, and Ed25519 keys
make attack SCENARIO=policy      # Run adaptive adversarial tampering from attacker harness
make load                        # Concurrent load & latency test (10, 50, 100 sessions)
make reproduce                   # Regenerate all comparative baseline tables and metrics
make test                        # Execute full regression test suite (296 tests)
```

### 5. Multi-Container Segmented Network Deployment (`docker-compose.yml`)
To run the full segmented multi-container environment (Gateway, DB, Append-Only Vault, Anchor Witness, Watcher, Agent, Attacker):
```bash
docker compose up --build -d
```

### 6. Launch the Enterprise SOC Dashboard
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
* **SOC Audit & Dossiers**: Live telemetry tracking IP origin, dwell times, and downloadable incident reports (JSON, Markdown, PDF).

---

## Security Model & Claims

| Attack Scenario | Vulnerability Without AegisMem | AegisMem Mitigation | Defended Evidence |
|---|---|---|---|
| **Direct Policy Tampering** (e.g. refund window 30 $\rightarrow$ 180 days) | Bot serves modified policy; direct financial loss | Watcher detects hash mismatch; read-path gate blocks access; TCRP rolls back to verified version. | 0 wrong answers served across 10/50/100 concurrency tiers |
| **Historical Store Tampering** ($k=1$ attack on SQLite) | Single-store resolvers fail or quarantine permanently | TCRP falls back to `ReplicatedTrustVault`, verifies Ed25519 signature, and auto-repairs SQLite. | 100% recovery accuracy vs 90.9% for unanchored TCRP |
| **Conversational Injection** (Customer talks agent into storing "policy") | Agent adopts customer claim as company rule | Memory class authority tiers prevent conversation notes from writing to policy classes. | MINJA injection blocked fail-closed (Exp 2) |
| **Total Multi-Store Compromise** ($k=n$) | Undetected corruption served to customers | All unverified candidates fail Ed25519 validation; system safely quarantines memory (0% forged data served). | Level 5 Fail-safe quarantine activated (0 exposure) |
| **Legitimate Staff Policy Modification** (Shipping SLA update) | Heuristic rule-based systems falsely flag numerical changes | Cryptographic owner authorization with Ed25519 and nonce registry verifies legitimate updates. | 0.0% False Rollback Rate (FRR) vs 10.0% for rule heuristics |

---

## Milestone Progress Matrix

| Milestone | Capability | Status | Acceptance Verification |
|---|---|---|---|
| **M0** | Packaging, requirements pinning, hygiene, and vulnerability baseline | ✅ Complete | Clean virtualenv, 27 tests pass, `test_trusted_version_gap.py` |
| **M1** | Portable storage adapter (SQLite & PostgreSQL) | ✅ Complete | Unified MemoryStore interface, identical test suites pass |
| **M2** | Ed25519 cryptographic owner authorization & nonce registry | ✅ Complete | Cryptographic signing, replay/skew rejection, admin client |
| **M3** | Trust anchor, append-only vault & 5-level recovery ladder | ✅ Complete | Independent countersignatures, key revocation registry |
| **M4** | Event-driven real-time detection telemetry | ✅ Complete | Write $\rightarrow$ Detect $\rightarrow$ Recover telemetry, sub-5ms detection |
| **M5** | Verify-on-read ReadPathGate & memory authority tiers | ✅ Complete | Fail-closed read gate, MINJA injection prevention, cache invalidation |
| **M6** | Customer support domain taxonomy & RAG evaluator | ✅ Complete | 330 benchmark queries, 6 memory classes, pluggable LLM |
| **M7** | Adaptive attacker suite & forensic session timeline | ✅ Complete | Read logger, dwell-time analysis, adaptive attackers A/B/C |
| **M8** | 5 Comparative baselines & statistical benchmark reproduction | ✅ Complete | AegisMem: 0% ASR, 100% Rec, 0% FRR vs Retain/Rule/CAMS/NoAnchor |
| **M9** | Concurrent load generator & latency profile (10/50/100 sessions) | ✅ Complete | Sub-50ms self-healing under load, zero exposure window |
| **M10** | Forensic incident dossiers (JSON/MD/PDF), SOC feed & container demo | ✅ Complete | 7-step enterprise demo, `make demo`, RAG metrics per class |
| **M11** | Research paper documentation, threat model, limitations & claims matrix | ⏳ Next | Formal threat model, real-world bounds, reproducibility guide |

