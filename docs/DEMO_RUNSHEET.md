# AegisMem Reviewer Demonstration Run Sheet

**Target Audience:** PhD Academic Reviewer / Evaluation Committee  
**Evaluation Deployment:** Docker Compose on Windows PowerShell  
**Repository:** `Potharaju-Vinay/AegisMem-Research`  
**Primary Interface:** Windows PowerShell terminal with live container verification; auxiliary reviewer dashboard at `http://127.0.0.1:5173/`

---

## 1. Ground Rules & Reviewer Vocabulary ("Do Not Say" List)

To preserve scientific credibility, adhere strictly to these terminology boundaries:

| Strictly Prohibited Term | Approved Scientific Term | Why the Distinction Matters |
| :--- | :--- | :--- |
| **"Air-gapped"** | **"Network-segmented isolated bridge"** | The vault database sits on an internal Docker network bridge (`vault-net`) with unmapped host ports, not physical galvanic isolation. |
| **"Kali Linux"** | **"Debian container (`aegismem-attacker`)"** | The container image is `debian:bookworm-slim` equipped with `curl`, `jq`, and `python3`. |
| **"Production-ready"** | **"Research benchmark prototype"** | The system is designed for empirical validation and research reproducibility. |
| **"Works in any environment"** | **"Evaluated on Docker Compose on Windows PowerShell"** | Claims must be scoped to verified operational environments. |
| **"Instantly"** | **"Measured median latency: 991.83 ms (p95: 1,280.19 ms)"** | Recovery requires algorithmic TCRP evaluation and cryptographic validation. |
| **"Immutable database"** | **"Tamper-evident append-only provenance with out-of-band verification"** | The underlying PostgreSQL store is mutable, which is why cryptographic verification is required. |
| **Unverified Numbers** | **Quote ONLY numbers from `demo_runs/`** | Never invent latency, confidence scores, or trial counts. |

---

## 2. Step-by-Step Demonstration Script

### Step 1: Preflight Deployment Hardening Audit
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/preflight.ps1
  ```
* **Expected Runtime:** ~2 – 3 seconds
* **What to Say:**
  > *"We begin by verifying the physical runtime truth of our deployment. Rather than assuming services are running, this preflight script dynamically queries Docker Compose to inspect all 9 active containers, their assigned network bridges, port mappings, and health status. Notice that `vault-db` has no mapped host ports and resides exclusively on `vault-net`, while `memory-db` is strictly bound to `127.0.0.1`."*
* **Expected Verification:** Exit code `0`; confirms 9 running services with zero security mapping violations.

---

### Step 2: Network-Segmented Isolation Proof
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/prove_isolation.ps1
  ```
* **Expected Runtime:** ~4 – 5 seconds
* **What to Say:**
  > *"Next, we prove network segmentation. The attacker container on `public-net` attempts to resolve and connect to `vault-db` over both DNS and direct IP socket. As shown, both fail with connection timeouts. Meanwhile, our recovery service on `vault-net` connects successfully. Note that we disclose an architectural characteristic: the anchor container serves as a witness container whose cryptographic validation is executed in-process rather than via a dedicated TCP socket daemon."*
* **Expected Verification:** Tests A, B, C, D, E, F, H pass; Test G is explicitly reported as an in-process witness.

---

### Step 3: Database Isolation & Deterministic Baseline
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  ```
* **Expected Runtime:** ~5 – 7 seconds
* **What to Say:**
  > *"To ensure reproducibility, we seed the demo database `aegismem_demo` with our canonical enterprise customer-support policies. The script enforces a strict target guard: it unconditionally rejects any reset targeting `aegismem_live`, preserving all 171 historical audit records. It executes twice to prove mathematical idempotence across content hashes and schema rows."*
* **Expected Verification:** 9 memories seeded at `v1`, active status, trust `1.00`, suspicion `0.00`, and all 6 incident/audit tables verified empty (0 rows).

---

### Step 4: Baseline Support Agent Question Answering
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/ask_agent.ps1 -Question "I bought an item 45 days ago. Can I get a refund?"
  ```
* **Expected Runtime:** ~1 – 2 seconds
* **What to Say:**
  > *"Here is the baseline customer support interaction. A customer requests a refund 45 days after purchase. The support agent retrieves `POLICY-001` v1 through the AegisMem ReadPathGate. The gate validates the Ed25519 manifest and genesis provenance. Under the enterprise 30-day policy, the agent correctly answers: REFUND DENIED."*
* **Expected Verification:** Decision `REFUND DENIED`, memory version `v1`, verification status `VERIFIED`.

---

### Step 5: Legitimate Owner Policy Update
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/owner_update.ps1
  ```
* **Expected Runtime:** ~3 – 4 seconds
* **What to Say:**
  > *"A critical requirement for persistent memory security is that legitimate business updates must not trigger false rollbacks. Here, the enterprise owner signs a policy change extending the refund window from 30 days to 45 days using Ed25519 digital signatures. The update is accepted as v3, active, with exactly 0 false rollbacks. When we re-ask the 45-day refund question, the agent now correctly answers: REFUND ALLOWED. Three adversarial rejection tests (tampered payload, replayed nonce, stale timestamp) are also asserted and rejected with HTTP 401/403."*
* **Expected Verification:** False-rollback count = `0`; agent answers `REFUND ALLOWED`; 3 rejection tests pass.

---

### Step 6: Baseline Harm Demonstration (Protection OFF)
* **Command:**
  ```powershell
  # Reset to 30-day baseline first
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  # Execute unprotected attack
  powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Protection off
  ```
* **Expected Runtime:** ~3 – 4 seconds
* **What to Say:**
  > *"To establish empirical harm, we disable AegisMem protection. The attacker container injects an unauthorized SQL modification into `POLICY-001`, altering the refund window from 30 to 180 days. A customer asks: 'I bought an item 60 days ago. Can I get a refund?' Because protection is disabled, the agent uses the poisoned memory and responds: REFUND ALLOWED. This demonstrates real financial exposure under baseline unprotected conditions (exposure window = 1)."*
* **Expected Verification:** Decision `REFUND ALLOWED`, exposure count = 1.

---

### Step 7: Full Autonomous Self-Healing Chain (Protection ON)
* **Command:**
  ```powershell
  # Reset to baseline
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  # Execute full autonomous protected lifecycle
  powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Mode autonomous -Protection on
  ```
* **Expected Runtime:** ~2 – 4 seconds
* **What to Say:**
  > *"Now we execute the identical attack with AegisMem autonomous protection active. The background watcher continuously scans and self-heals without scripted orchestrations. Notice the asserted telemetry: First, attacker write is captured with the real container IP from public-net (e.g. 172.18.0.x). Second, continuous 50ms customer query probes are intercepted by ReadPathGate—measuring real zero financial exposure (0 wrong answers). Third, the background watcher spots the compromise with suspicion score 1.0. Fourth, TCRP evaluates candidate costs and restores the verified genesis state from the Trust Vault on vault-net. Fifth, memory is restored to active v3. Sixth, customer queries again and receives REFUND DENIED, perfectly matching baseline enterprise policy. All timestamps are extracted from PostgreSQL rows."*
* **Expected Verification:** Autonomous self-healing completes with watcher active; measured exposure window = 0; post-recovery agent decision = `REFUND DENIED`.

---

### Step 8: Database-Driven Forensics Dossier
* **Command:**
  ```powershell
  Get-Content -Path (Get-ChildItem -Path demo_runs -Filter incident_report.md -Recurse | Select-Object -Last 1).FullName
  ```
* **Expected Runtime:** Instant
* **What to Say:**
  > *"Milestone D7 proves that every field in our incident dossier is synthesized strictly from recorded database rows in `memory_access_events`, `attack_events`, `soc_alerts`, and `recovery_events`. The unified diff, chronological timeline, dwell time, and candidate costs reflect live database state. Deleting or filtering the database rows removes the data entirely—proving zero hardcoding."*
* **Expected Verification:** Unified git diff, real timeline timestamps, zero exposure recorded.

---

### Step 9: Trusted-Version Attacks Evaluation
* **Command:**
  ```powershell
  docker exec aegismem-gateway python scripts/test_trusted_version_attacks.py
  ```
* **Expected Runtime:** ~2 – 3 seconds
* **What to Say:**
  > *"To evaluate historical research gaps, we run two adversarial attacks against the deployed resolver: Attack A injects a malicious ancestor v1 with forged active/trust SQL columns. AegisMem rejects it because it lacks an owner digital signature. Attack B rewrites history with recomputed SHA-256 hashes. Although internal hash chaining appears consistent, AegisMem detects and rejects it against out-of-band signed integrity manifests. Both attacks are defended."*
* **Expected Verification:** Both Attack A and Attack B report `DEFENDED (PASS)`.

---

### Step 10: Repeated Benchmark Trials
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/repeat_trials.ps1 -N 20
  ```
* **Expected Runtime:** ~140 seconds (~2.3 minutes)
* **What to Say:**
  > *"To demonstrate statistical rigor beyond a single run, we execute repeated independent trials from a clean state. Across all trials, AegisMem records measured self-healing latencies and customer exposure window from live database event rows. Most critically, across all protected trials, the customer policy exposure window is verified at 0 wrong answers served."*
* **Expected Verification:** 20 / 20 successes; 0 failures; max exposure window = 0; CSV written to `demo_runs/<timestamp>_trials/trials.csv`.

---

### Step 11: Reviewer Dashboard Verification
* **Action:** Open browser at `http://127.0.0.1:5173/` (or `http://localhost:5173/`).
* **What to Say:**
  > *"Finally, we inspect the live reviewer dashboard running as a native Compose service on `127.0.0.1:5173`. The dashboard provides operators with live visibility into: (1) container services and health, (2) the active database name (`aegismem_demo`), (3) persistent memory versions showing real runtime progression (v1 baseline -> v2 attacked -> v3 restored), (4) real adversary container IP (e.g. 172.18.0.x on public-net) without hardcoded Kali assumptions, (5) real-time incident timelines with dwell times, and (6) the interactive AI Assistant security gate. Notice that all telemetry reflects the database rows generated during our live runs."*
* **Expected Verification:** Overview metrics, active database indicator (`aegismem_demo`), Live Recovery three-state comparison (v1 -> v2 -> v3), real container IP/port, and SOC Audit log table are active.

