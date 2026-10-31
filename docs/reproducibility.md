# Comprehensive Reproducibility Guide

This document details the exact environment specifications, dependency pins, configuration flags, random seeds, and execution commands required to independently replicate every empirical metric, latency table, and forensic dossier reported in our research paper.

---

## 1. Experimental Environment & System Specifications

* **Operating System:** Windows 11 Enterprise (x64) / Ubuntu 22.04 LTS via WSL2 (Linux kernel 5.15+).
* **Python Runtime:** Python 3.12 or Python 3.13 (CPython 64-bit).
* **Container Runtime:** Docker Desktop 4.30+ with Docker Compose v2.
* **Database Backends:** SQLite 3.42+ (in-process) and PostgreSQL 16.2 (containerized).
* **Cryptographic Engine:** OpenSSL 3.0+ via Python `cryptography` 50.0.2 (Ed25519 & SHA-256).

---

## 2. Installation & Dependency Pinning

Clone the repository and initialize an isolated virtual environment:

```bash
# Clone the repository
git clone https://github.com/Potharaju-Vinay/AegisMem-Research.git
cd AegisMem-Research

# Create and activate virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install strictly pinned dependencies
pip install --no-cache-dir -r requirements.txt
```

---

## 3. Seed Configuration & Determinism Controls

To eliminate statistical artifacts and random variance:
* **Evaluation Random Seeds:** `[42, 101, 202, 303, 404]`
* **LLM Inference Temperature:** `0.0` (greedy deterministic decoding)
* **Statistical Tests:**
  - McNemar's test with continuity correction for paired binary outcomes ($\text{ASR}$, $\text{Recovery}$).
  - Wilcoxon signed-rank test for paired continuous latency metrics.

---

## 4. Single-Command Experiment Execution

All experiments can be reproduced using standard Python entrypoints or the provided `Makefile`.

### Experiment 1: Storage Adapter Portability
Validates that the storage adapter interface (`core/memory/store.py`) passes identical attack and integrity suites on both SQLite and PostgreSQL backends:
```bash
python -m pytest tests/test_storage_adapter.py -v
```
*Expected Result:* 5 passing tests, zero database-dependent regressions.

---

### Experiment 2: Customer Support Domain Benchmark & Baseline Accuracy
Evaluates the enterprise customer support agent performing RAG through the `ReadPathGate` across 330 benchmark queries covering 6 memory classes:
```bash
python -m pytest tests/test_support_domain_m6.py -v
```
*Expected Result:* 100.0% clean accuracy, MINJA prompt injection blocked fail-closed.

---

### Experiment 3: Comparative Baselines & Statistical Significance
Executes the 5 comparative baselines (`retain_only`, `rule_based_rollback`, `detection_only`, `tcrp_no_anchor`, and `aegismem_tcrp_anchor`) across 5 seeds:
```bash
# Run benchmark CLI
python evaluation/run_domain_benchmarks.py

# Or via Makefile:
make reproduce
```
*Output Artifacts Generated:*
* Markdown Summary: `data/domain_benchmark_results.md`
* Machine-Readable CSV: `data/domain_benchmark_results.csv`
* Expected Metrics: AegisMem achieves **0.0% ASR, 100.0% Recovery Accuracy, 0.0% False Rollbacks, and 0 Exposure Window**.

---

### Experiment 4: Concurrent Load & Latency Profiling (10, 50, 100 Sessions)
Launches concurrent customer sessions with mid-run attack injection (`POLICY-REFUND-001` $30\text{d} \rightarrow 180\text{d}$):
```bash
# Run load testing CLI
python evaluation/run_load_test.py

# Or via Makefile:
make load
```
*Output Artifacts Generated:*
* Markdown Latency Table: `data/load_latency_benchmarks.md`
* CSV Latency Data: `data/load_latency_benchmarks.csv`
* Expected Metrics: Exactly **0 wrong answers served** across all tiers; sub-50ms self-healing recovery duration ($26.08\text{ ms} - 35.22\text{ ms}$).

---

### Experiment 5: End-to-End 7-Step Enterprise Reviewer Demo
Executes the full reviewer demo lifecycle: startup $\rightarrow$ clean agent queries $\rightarrow$ authorized staff update $\rightarrow$ mid-run database tampering $\rightarrow$ fail-closed read gate interception (0 wrong answers) $\rightarrow$ self-healing recovery $\rightarrow$ restored correct answer $\rightarrow$ multi-format forensic incident dossier export:
```bash
# Run demo script
python scripts/demo_end_to_end.py

# Or via Makefile:
make demo
```
*Output Artifacts Generated:*
* Incident JSON: `data/incidents/INC-DEMO-*.json`
* Incident Markdown: `data/incidents/INC-DEMO-*.md`
* Incident PDF Dossier: `data/incidents/INC-DEMO-*.pdf`

---

### Complete Regression Test Suite
Executes all 296 unit, cryptographic, and integration tests across the repository:
```bash
pytest tests/ -q
```
*Expected Result:* **296 passed, 0 failures**.
