# AegisMem Reviewer Demonstration Run Sheet

**Target Audience:** PhD Academic Reviewer / Evaluation Committee  
**Evaluation Deployment:** Docker Compose on Windows PowerShell  
**Repository:** `Potharaju-Vinay/AegisMem-Research`  
**Primary Interface:** Windows PowerShell terminal with live container verification; auxiliary reviewer dashboard at `http://127.0.0.1:5173/`  
**Latest Empirical Dataset:** `demo_runs/evaluation/benchmark_trials.csv` ($n = 200$ trials)

---

## 1. Ground Rules & Reviewer Vocabulary ("Do Not Say" List)

To preserve scientific credibility, adhere strictly to these terminology boundaries:

| Strictly Prohibited Term | Approved Scientific Term | Why the Distinction Matters |
| :--- | :--- | :--- |
| **"Air-gapped"** | **"Network-segmented isolated bridge (`vault-net`)"** | The vault database sits on an internal Docker network bridge (`vault-net`) with unmapped host ports, not physical galvanic isolation. |
| **"Kali Linux"** | **"Debian container (`aegismem-attacker`)"** | The container image is `debian:bookworm-slim` equipped with `curl`, `jq`, and `python3`. |
| **"Production-ready"** | **"Research benchmark prototype"** | The system is designed for empirical validation and research reproducibility. |
| **"Works in any environment"** | **"Evaluated on Docker Compose on Windows PowerShell"** | Claims must be scoped to verified operational environments. |
| **"Sub-second" / "Instantly"** | **"Measured median latency: 2808.70 ms (p95: 3694.13 ms)"** | Recovery requires algorithmic TCRP evaluation, dependency graph checking, and cryptographic validation. |
| **"Zero exposure" (unqualified)** | **"0 wrong answers out of 500 customer probes sent across 50 autonomous trials"** | Customer exposure is an empirical measurement evaluated by continuous 50 ms query probes. |
| **"Real-time"** | **"Event-hook / 500 ms background polling watcher"** | Detection is driven by PostgreSQL database event hooks and periodic watcher polling. |
| **"Immutable database"** | **"Tamper-evident append-only provenance with out-of-band verification"** | The underlying PostgreSQL store is mutable, which is why cryptographic verification is required. |
| **Unverified Numbers** | **Quote ONLY numbers from `demo_runs/evaluation/`** | Never invent latency, confidence scores, or trial counts. |

---

## 2. What is NOT Implemented (Honest Architectural Scope)

1. **Physical Air-Gap:** AegisMem uses Docker network segmentation (`vault-net` internal bridge with no exposed host ports). It does not use dedicated optical data diodes or disconnected physical hardware.
2. **Multi-Datacenter Byzantine Fault Tolerance (BFT):** AegisMem uses local container-level multi-service consensus (independent anchor witness, recovery engine, and gateway). It is not an enterprise distributed Raft/Paxos cluster across geographically separate clouds.
3. **Hardware Enclaves (SGX/Nitro):** Cryptographic keys are isolated via POSIX permissions and filesystem mount boundaries on the host, not confidential computing hardware enclaves.
4. **Kernel-Level eBPF Interception:** Tamper detection uses transactional PostgreSQL event hooks and watcher polling (~500 ms loop), not kernel memory bus tracing.
5. **Full-Duplex WebSocket Push to Dashboard:** The reviewer dashboard polls the gateway REST API (`/api/status`, `/api/incidents`) at 1–2 second intervals.

---

## 3. Step-by-Step Demonstration Script

### Step 1: Preflight Deployment Hardening Audit
* **Mode:** STEPPED (Static environment audit)
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
* **Mode:** STEPPED (Security boundary assertion)
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/prove_isolation.ps1
  ```
* **Expected Runtime:** ~4 – 5 seconds
* **What to Say:**
  > *"Next, we prove network segmentation. The attacker container on `public-net` attempts to resolve and connect to `vault-db` over both DNS and direct IP socket. As shown, both fail with connection timeouts. Meanwhile, our recovery service on `vault-net` connects successfully. Furthermore, we verify that the gateway has no private key files and cannot write to the trust vault."*
* **Expected Verification:** All isolation assertions pass; attacker cannot reach vault; gateway cannot access private keys.

---

### Step 3: Database Isolation & Deterministic Baseline
* **Mode:** STEPPED (State reset)
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  ```
* **Expected Runtime:** ~5 – 7 seconds
* **What to Say:**
  > *"To ensure reproducibility, we seed the demo database `aegismem_demo` with our canonical enterprise customer-support policies. The script enforces a strict target guard: it unconditionally rejects any reset targeting `aegismem_live`, preserving all 171 historical audit records. It executes twice to prove mathematical idempotence across content hashes and schema rows."*
* **Expected Verification:** 9 memories seeded at `v1`, active status, trust `1.00`, suspicion `0.00`, and all incident/audit tables verified empty.

---

### Step 4: Baseline Support Agent Question Answering
* **Mode:** STEPPED (Clean read path)
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
* **Mode:** STEPPED (Authorized mutation verification)
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/owner_update.ps1
  ```
* **Expected Runtime:** ~3 – 4 seconds
* **What to Say:**
  > *"A critical requirement for persistent memory security is that legitimate business updates must not trigger false rollbacks. Here, the enterprise owner signs a policy change extending the refund window from 30 days to 45 days using Ed25519 digital signatures. In our evaluation across 100 legitimate updates, exactly 0 false rollbacks were triggered. When we re-ask the 45-day refund question, the agent correctly answers: REFUND ALLOWED. Three adversarial rejection tests (tampered payload, replayed nonce, stale timestamp) are also asserted and rejected with HTTP 401."*
* **Expected Verification:** False-rollback count = `0`; agent answers `REFUND ALLOWED`; rejection tests pass.

---

### Step 6: Baseline Harm Demonstration (Protection OFF — Negative Control)
* **Mode:** STEPPED (Negative control demonstration)
* **Command:**
  ```powershell
  # Reset to 30-day baseline first
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  # Execute unprotected attack
  powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Protection off
  ```
* **Expected Runtime:** ~3 – 4 seconds
* **What to Say:**
  > *"To establish empirical harm, we disable AegisMem protection. The attacker container injects an unauthorized SQL modification into `POLICY-001`, altering the refund window from 30 to 180 days. A customer asks: 'I bought an item 60 days ago. Can I get a refund?' Because protection is disabled, the agent uses the poisoned memory and responds: REFUND ALLOWED. Across our 50-trial negative control benchmark, protection-off resulted in 100.0% failure with a mean measured exposure of 7.04 wrong answers per trial (352 total exposures across 352 probes sent). This proves our measurement harness detects real policy violations."*
* **Expected Verification:** Decision `REFUND ALLOWED`, exposure count $\ge 1$.

---

### Step 7: Full Autonomous Self-Healing Chain (Protection ON)
* **Mode:** AUTONOMOUS (Watcher active; script only attacks and observes)
* **Command:**
  ```powershell
  # Reset to baseline
  powershell -ExecutionPolicy Bypass -File scripts/reset_and_seed.ps1
  # Execute full autonomous protected lifecycle
  powershell -ExecutionPolicy Bypass -File scripts/run_incident.ps1 -Mode autonomous -Protection on
  ```
* **Expected Runtime:** ~3 – 5 seconds
* **What to Say:**
  > *"Now we execute the identical attack with AegisMem autonomous protection active. The background watcher runs continuously without scripted orchestration. Notice the asserted telemetry: First, attacker write is captured with the real container IP from public-net. Second, continuous 50ms customer query probes are intercepted by ReadPathGate—measuring 0 wrong answers served during the incident. Third, the background watcher spots the compromise with suspicion score 1.0. Fourth, TCRP evaluates candidate costs and restores the verified state from the Trust Vault. Fifth, memory is restored to active v3. Sixth, customer queries again and receives REFUND DENIED, matching enterprise policy. In our 50 autonomous trials, mean total duration was 2804.55 ms with median 2808.70 ms and zero customer exposures out of 500 probes sent."*
* **Expected Verification:** Autonomous self-healing completes with watcher active; measured exposure = 0; post-recovery agent decision = `REFUND DENIED`.

---

### Step 8: Database-Driven Forensics Dossier
* **Mode:** STEPPED (Forensic verification)
* **Command:**
  ```powershell
  Get-Content -Path (Get-ChildItem -Path demo_runs -Filter incident_report.md -Recurse | Select-Object -Last 1).FullName
  ```
* **Expected Runtime:** Instant
* **What to Say:**
  > *"Every field in our incident dossier is synthesized strictly from recorded database rows in `memory_access_events`, `attack_events`, `soc_alerts`, and `recovery_events`. The unified diff, chronological timeline, dwell time, and candidate costs reflect live database state. An empty session produces zero data—proving zero hardcoding."*
* **Expected Verification:** Unified git diff, real timeline timestamps, zero exposure recorded.

---

### Step 9: Trusted-Version Attacks Evaluation
* **Mode:** STEPPED (Adversarial edge-case tests)
* **Command:**
  ```powershell
  docker exec aegismem-gateway python scripts/test_trusted_version_attacks.py
  ```
* **Expected Runtime:** ~2 – 3 seconds
* **What to Say:**
  > *"To evaluate historical research gaps, we run two adversarial attacks against the deployed resolver: Attack A injects a malicious ancestor v1 with forged active/trust SQL columns. AegisMem rejects it because it lacks an owner digital signature. Attack B rewrites history with recomputed SHA-256 hashes. Although internal hash chaining appears consistent, AegisMem detects and rejects it against out-of-band signed integrity manifests. Both attacks are defended."*
* **Expected Verification:** Both Attack A and Attack B report `DEFENDED (PASS)`.

---

### Step 10: Repeated Benchmark Trials & Statistical Rigor
* **Mode:** AUTONOMOUS (Empirical statistical benchmark)
* **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/run_evaluation_benchmarks.py --trials 10
  ```
* **Expected Runtime:** ~8 – 12 minutes ($n = 200$ total trials across 4 defense stacks)
* **What to Say:**
  > *"To prove statistical rigor beyond a single trial, we execute 200 paired trials across 5 enterprise memories and 3 attack vectors. As recorded in `demo_runs/evaluation/benchmark_trials.csv`, AegisMem TCRP achieves 100.0% success (50/50) with 0 customer exposures out of 500 probes sent. Under McNemar's test, TCRP demonstrates statistically significant superiority over Rule-Based rollback (chi2 = 31.03, p = 2.54e-08) and Protection-Off (chi2 = 48.02, p = 4.22e-12)."*
* **Expected Verification:** Output written to `demo_runs/evaluation/`; statistical comparison generated in `demo_runs/evaluation/statistical_comparison.json`.

---

### Step 11: Reviewer Dashboard Verification
* **Action:** Open browser at `http://127.0.0.1:5173/` (or `http://localhost:5173/`).
* **What to Say:**
  > *"Finally, we inspect the live reviewer dashboard running as a native Compose service on `127.0.0.1:5173`. The dashboard displays real database state from `aegismem_demo`, showing persistent memory versions (v1 baseline -> v2 attacked -> v3 restored), real container IP from public-net, dwell times, and the interactive AI Assistant security gate without hardcoded IP or actor strings."*
* **Expected Verification:** Live Recovery three-state comparison (v1 -> v2 -> v3), real container IP/port, and SOC Audit log table reflect live database rows.
