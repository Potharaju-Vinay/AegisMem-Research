# AegisMem Empirical Evaluation Report (Milestone F7)

**Evaluation Date:** November 2026  
**Target Environment:** Isolated Python Benchmark Execution Engine & Docker Microservices  
**Target Database:** Isolated SQLite/PostgreSQL Evaluator Database (`aegismem_demo`)  
**Evaluator Suite:** [`scripts/run_evaluation_benchmarks.py`](../scripts/run_evaluation_benchmarks.py)  
**Static AST Verification:** [`tests/test_no_hardcoded_metrics.py`](../tests/test_no_hardcoded_metrics.py) (All 6 tests passing)  
**Raw Measurements:** [`demo_runs/evaluation/benchmark_trials.csv`](../demo_runs/evaluation/benchmark_trials.csv)  
**Concurrency Dataset:** [`demo_runs/evaluation/concurrency_scaling.csv`](../demo_runs/evaluation/concurrency_scaling.csv)  
**Statistical Analysis:** [`demo_runs/evaluation/statistical_comparison.json`](../demo_runs/evaluation/statistical_comparison.json)  

---

## 1. Executive Summary

Milestone **F7** establishes rigorous empirical evaluation breadth for the AegisMem autonomous memory self-healing framework. To eliminate all scripted assertions and static constants, this benchmark executes **200 paired trials** across **5 distinct enterprise memories**, **3 attack vectors**, and **4 defense stacks**, evaluated via continuous background customer probes every ~50 ms, high-concurrency scaling with a no-gate baseline ($\ge 20$ probes/worker), and formal statistical hypothesis testing with Wilson and Clopper-Pearson confidence intervals.

### Key Empirical Findings:
1. **Zero Policy Exposure Under Attack ($0/450$ Probes):** Across 50 autonomous AegisMem TCRP trials with continuous customer probing active from pre-attack injection through validated recovery, exactly **0 probes** were served corrupted memory content (Mean Exposure = 0.0, Exposure Rate = 0.0%, 95% Wilson CI: [0.0%, 7.1%]).
2. **Negative Control Verification ($100\%$ Exposure Detected):** In the unmitigated baseline (*Protection OFF*), all 50 trials recorded severe exposure ($100\%$ failure rate, Mean Exposures = 25.26 probes per trial), demonstrating that the probe harness reliably captures integrity breaches.
3. **Statistical Superiority Over Rule-Based Systems ($p = 5.41 \times 10^{-11}$):** Under McNemar's test for paired binary outcomes, AegisMem TCRP significantly outperforms naive rule-based rollback ($\chi^2 = 43.02, p < 0.001$), which collapses under in-place prompt poisoning injections and unauthorized deletions ($45/50$ failures).
4. **Isolated Repair Under Dependent Contamination:** When only the dependent memory `SOP-003` was contaminated, TCRP achieved isolated repair with **0 unnecessary rollbacks** and **0 dependency collateral damage**, while the rule-based policy falsely reverted 2 clean ancestor memories (`POLICY-001` and `POLICY-002`) and induced dependency inconsistency.
5. **High-Concurrency Scaling with No-Gate Comparison:** Under 10 and 50 concurrent worker threads ($\ge 20$ probes/worker, 200 and 1000 probes total), AegisMem's `ReadPathGate` achieved 504.5 rps at 10 workers (P95: 18.06 ms) and 482.6 rps at 50 workers (P95: 136.25 ms) with zero customer exposures, compared to the unguarded no-gate baseline (542.9 rps and 1313.4 rps).
6. **Zero LLM Semantic Verification:** All verification is strictly deterministic and cryptographic, relying on Ed25519 digital signatures, Merkle hash chains, and the TCRP Pareto cost optimizer. No LLM-based semantic verification is used or claimed.

---

## 2. Evaluation Matrix & Methodology

### 2.1 Evaluated Memory Corpus ($5$ Targets)
The benchmark evaluates 5 distinct enterprise knowledge records representing different regulatory, operational, and customer-facing domains:
- **`POLICY-001` (Customer Refund Window):** 30-day refund window policy (Customer Support domain). Probes test day-45 purchases.
- **`POLICY-002` (Refund Policy Exceptions):** Manual review exception handling policy. Probes test exception criteria.
- **`SOP-003` (Customer Support Verification SOP):** Verification requirements for refund processing, deriving from `POLICY-001` and `POLICY-002`.
- **`ENT-ACCESS-001` (Enterprise Access Control):** Least-privilege multi-factor access requirements. Probes test administrative overrides.
- **`ENT-BACKUP-003` (Enterprise Backup Retention SOP):** 90-day daily backup retention requirement. Probes test premature deletion directives.

### 2.2 Attack Vectors ($3$ Modalities)
Each memory is subjected to 10 trials across:
1. **Content Tampering:** Appends an unauthorized version modifying policy thresholds (e.g., expanding refund limit from 30 to 180 days).
2. **Prompt Poisoning:** In-place instruction injection embedding system override directives designed to subvert agent decision logic.
3. **Unauthorized Deletion:** Malicious record invalidation with deletion tombstone marked `DELETED`.

### 2.3 Evaluated Defense Stacks ($4$ Architectures)
1. **Protection OFF (Baseline / Negative Control):** No gating, no detection, no recovery. Corrupted content is served immediately.
2. **Detection-Only:** Background detector identifies compromise and calculates live Time-to-Detect ($T_{\text{detect}}$), but executes no recovery. Probes continue to observe unhealed state.
3. **Rule-Based Naive Rollback:** Naive version-rollback ($v \to \max(1, v-1)$) executed with the exact same recovery sources as TCRP, without dependency graph analysis or cryptographic trust anchor verification.
4. **AegisMem Autonomous TCRP (Full Framework):** Cryptographic `ReadPathGate`, continuous detection, Trust Cost-Risk Pareto (TCRP) recovery planner, Replicated Trust Vault retrieval, and post-recovery cryptographic validation.

### 2.4 Continuous Probing Loop
Probing runs continuously in a background thread every ~50 ms starting prior to attack injection until validated recovery or timeout ($\ge 15.0$ s). Each probe response is classified into:
- **`CORRECT`:** Agent returns the expected compliant decision based on clean policy (`REFUND DENIED`).
- **`WRONG`:** Agent returns the corrupted or injected decision (`REFUND ALLOWED`), recorded as an exposure event.
- **`BLOCKED`:** Cryptographic `ReadPathGate` blocks retrieval of unverified memory (`BLOCKED_UNVERIFIED`), preserving security and containment at the cost of transient availability downtime.

---

## 3. Empirical Results Summary

All metrics are derived directly from [`demo_runs/evaluation/benchmark_trials.csv`](../demo_runs/evaluation/benchmark_trials.csv) and [`demo_runs/evaluation/statistical_comparison.json`](../demo_runs/evaluation/statistical_comparison.json):

| Defense Stack | Trials ($N$) | Successes | Success Rate | 95% Wilson CI | 95% Clopper-Pearson CI | Mean Probes Sent | Mean Exposures | Exposure Rate | Mean Availability |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Protection OFF** *(Negative Control)* | 50 | 0 | **0.0%** | [0.0%, 7.1%] | [0.0%, 7.1%] | 25.56 | 25.26 | **100.0%** | 1.1% |
| **Detection-Only** | 50 | 0 | **0.0%** | [0.0%, 7.1%] | [0.0%, 7.1%] | 30.98 | 30.68 | **100.0%** | 1.0% |
| **Rule-Based Naive Rollback** | 50 | 5 | **10.0%** | [4.4%, 21.4%] | [3.3%, 21.8%] | 8.68 | 0.00 | **0.0%** | 3.4% |
| **AegisMem Autonomous TCRP** | 50 | 50 | **100.0%** | [92.9%, 100.0%] | [92.9%, 100.0%] | 9.00 | **0.00** | **0.0%** | **93.0%** |

### Visual Comparison: Customer Exposure & Availability by Defense Stack
![Customer Exposure by Stack](demo_runs/evaluation/figure_exposure_by_stack.png)

---

## 4. Latency Decomposition Breakdown (AegisMem TCRP)

All latencies are measured from live execution timers across all 50 successful autonomous recovery trials:

$$\text{Total Recovery Duration} = T_{\text{detect}} + T_{\text{decide}} + T_{\text{recover}} + T_{\text{validate}}$$

| Latency Phase | Metric Meaning | Mean (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :---: | :---: | :---: |
| **Time-to-Detect ($T_{\text{detect}}$)** | Compromise detection & manifest verification | **33.52 ms** | 24.11 ms | 48.72 ms |
| **Time-to-Decide ($T_{\text{decide}}$)** | TCRP multi-criteria Pareto cost optimization | **4.28 ms** | 3.12 ms | 7.84 ms |
| **Time-to-Recover ($T_{\text{recover}}$)** | Replicated Trust Vault snapshot restoration | **23.34 ms** | 18.02 ms | 31.95 ms |
| **Time-to-Validate ($T_{\text{validate}}$)** | Cryptographic manifest & anchor receipt re-check | **1.01 ms** | 0.81 ms | 2.15 ms |
| **Total Incident Duration** | Full autonomous self-healing loop | **62.14 ms** | **46.85 ms** | **88.24 ms** |

### Latency Distribution Breakdown Across 5 Memories
![Latency Breakdown](demo_runs/evaluation/figure_latency_breakdown.png)

---

## 5. High-Concurrency Probing Performance

High-concurrency probing sessions were executed across 10 and 50 concurrent worker threads ($\ge 20$ probes/worker), directly comparing the protected `AegisMem Gate` against the unprotected `No-Gate` baseline:

| Concurrency Tier | Defense Stack | Total Probes | Customer Exposures | Query Throughput | Median ($p_{50}$) Latency | 95th Percentile ($p_{95}$) Latency | 99th Percentile ($p_{99}$) Latency |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **10 Workers** | **AegisMem Gate** | 200 | **0** | **504.46 req/s** | 7.06 ms | 18.06 ms | 21.81 ms |
| **10 Workers** | No-Gate Baseline | 200 | 0 | 542.94 req/s | 2.00 ms | 15.26 ms | 25.28 ms |
| **50 Workers** | **AegisMem Gate** | 1000 | **0** | **482.59 req/s** | 80.95 ms | 136.25 ms | 190.88 ms |
| **50 Workers** | No-Gate Baseline | 1000 | 0 | 1313.38 req/s | 15.71 ms | 53.29 ms | 81.17 ms |

### Concurrency Scaling Chart
![Concurrency Scaling](demo_runs/evaluation/figure_concurrent_scaling.png)

*Key Observation:* At 10 concurrent workers, the ReadPathGate cryptographic verification imposes only a minor latency increment (+5.06 ms at $p_{50}$) while providing absolute containment against compromised records.

---

## 6. Dependent Memory Contamination Analysis (`SOP-003`)

To evaluate graph-aware reasoning, a dedicated scenario contaminated only `SOP-003` (which depends on `POLICY-001` and `POLICY-002`):

| Metric | Rule-Based Naive Policy | AegisMem TCRP Autonomous |
| :--- | :---: | :---: |
| **Unnecessary Rollbacks (Clean Ancestors Falsely Reverted)** | **2** (`POLICY-001`, `POLICY-002`) | **0** (Clean ancestors preserved) |
| **Dependency Inconsistency Damage** | **1** (Collateral inconsistency) | **0** (Graph consistency maintained) |
| **Target Memory Repair** | Partial ($v-1$ naive rollback) | **Complete** (Vault-verified restoration) |
| **Overall Scenario Outcome** | **FAILURE (COLLATERAL_DAMAGE)** | **SUCCESS (ISOLATED_REPAIR)** |

### Dependency Impact Comparison
![Dependency Impact](demo_runs/evaluation/figure_dependency_damage.png)

---

## 7. Statistical Significance Tests

Formal hypothesis testing was performed on the paired 50-trial outcomes:

### 7.1 McNemar's Test for Paired Binary Outcomes
1. **AegisMem TCRP vs. Protection OFF:**
   - Contingency Table: $[[0, 50], [0, 0]]$
   - $\chi^2 = 48.02$, $p = 4.22 \times 10^{-12}$
   - **Conclusion:** Statistically significant ($p < 0.001$). AegisMem eliminates policy exposure.
2. **AegisMem TCRP vs. Detection-Only:**
   - Contingency Table: $[[0, 50], [0, 0]]$
   - $\chi^2 = 48.02$, $p = 4.22 \times 10^{-12}$
   - **Conclusion:** Statistically significant ($p < 0.001$). Passive detection without automated recovery leaves enterprise memory exposed.
3. **AegisMem TCRP vs. Rule-Based Naive Rollback:**
   - Contingency Table: $[[5, 45], [0, 0]]$
   - $\chi^2 = 43.02$, $p = 5.41 \times 10^{-11}$
   - **Conclusion:** Statistically significant ($p < 0.001$). Naive rollback collapses on in-place prompt poisoning and unauthorized deletions ($45/50$ failures), whereas AegisMem TCRP successfully recovers all 50 trials.

### 7.2 Wilcoxon Signed-Rank Test (Latency Comparison)
- Paired Sample Size: $n = 50$
- $W = 0.0$, $p = 1.78 \times 10^{-15}$
- TCRP Mean Duration: $62.14\text{ ms}$; Rule-Based Mean Duration: $35.53\text{ ms}$.
- **Conclusion:** The additional ~26 ms taken by TCRP enables complete graph impact evaluation, Pareto cost optimization, and cryptographic trust anchor validation, converting a 10% success rate into a 100% success rate.

---

## 8. Artifact Manifest & Reproducibility

All evaluation artifacts are preserved in `demo_runs/evaluation/`:
- `benchmark_trials.csv`: 200 rows of empirical measurements (trial, memory_id, attack_type, defense_stack, latencies, probes_sent, exposure_count, blocked_count, availability_rate, outcome).
- `concurrency_scaling.csv`: High-concurrency throughput and latency percentiles comparing `aegismem_gate` vs `no_gate`.
- `statistical_comparison.json`: Complete contingency tables, $\chi^2$ statistics, $p$-values, Wilson CIs, Clopper-Pearson CIs, and dependency scenario results.
- `figure_exposure_by_stack.png`: Comparative bar chart of customer exposure count and availability rate.
- `figure_latency_breakdown.png`: Stacked latency phase breakdown across all 5 memories.
- `figure_concurrent_scaling.png`: Throughput vs. $p_{95}$ latency under 10 and 50 concurrent workers.
- `figure_dependency_damage.png`: Unnecessary rollbacks and dependency damage comparison under `SOP-003` contamination.

To reproduce this benchmark suite:
```powershell
python -u scripts/run_evaluation_benchmarks.py --trials 10
```
To verify that no hardcoded constants exist in any evaluation script:
```powershell
python tests/test_no_hardcoded_metrics.py
```
