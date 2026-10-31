# Ethics, Data Governance & Responsible Research Statement

## 1. Dual-Use Analysis & Defensive Mission

AegisMem is developed as a defensive cybersecurity framework intended to safeguard persistent, stateful memories in enterprise AI systems against unauthorized tampering, poisoning, and supply-chain corruption.

### Risk Assessment & Mitigation
* **Defensive Focus:** The primary algorithmic contribution of this research—Trust-Cascaded Recovery Planning (TCRP) coupled with fail-closed Read-Path Gates and append-only Trust Vaults—is strictly protective. Its sole objective is detecting state contamination, pruning corrupted dependency cascades, and provably restoring authentic memory versions.
* **Attack Harness Containment:** The accompanying attack lab (`attack_lab/`) and adaptive attacker personas (Attackers A, B, and C) are created exclusively as an evaluation harness for benchmarking defensive resilience. All simulated attack scripts are hardcoded to communicate solely with local Docker bridge networks or isolated SQLite test databases (`localhost` / `127.0.0.1`). They cannot be pointed at external networks or third-party cloud services.

---

## 2. Privacy & Data Governance (Zero PII Guarantee)

* **No Real-World Customer PII:**
  - No personally identifiable information (PII), customer financial records, proprietary chat transcripts, or corporate confidential communications were collected, processed, or stored in this repository.
  - All customer profile records (`CUSTOMER_PROFILE`) and transaction references used during testing are entirely synthetic, generated using randomized identifiers (e.g., `CUST-PROFILE-1001`, `NONCE-DEMO-XXXX`).

---

## 3. Public Dataset Attribution & Open Source Licensing

The empirical query streams evaluated in Milestone M6, M7, and M8 incorporate standard open-access benchmark corpora under permissive academic research licenses:

1. **Bitext Customer Support LLM Chatbot Training Dataset:**
   - **Repository:** `bitext/Bitext-customer-support-llm-chatbot-training-dataset` on Hugging Face.
   - **License:** Community Data License Agreement – Sharing – Version 1.0 (CDLA-Sharing-1.0).
   - **Usage:** Provides natural language intent diversity and realistic query syntaxes across 27 customer support intents.

2. **BANKING77 Dataset:**
   - **Authors:** Iñigo Casanueva, Tadas Temčinas, Daniela Gerz, Matthew Henderson, Ivan Vulić (PolyAI).
   - **Repository:** `PolyAI/banking77` on Hugging Face / GitHub.
   - **License:** Creative Commons Attribution 4.0 International (CC BY 4.0).
   - **Usage:** Evaluated for fine-grained intent classification and customer support phrasing variance across 13,083 queries over 77 intents.

3. **Synthetic Policy & FAQ Corpus:**
   - All underlying policies (`POLICY-*`), warranty rules, return conditions, and FAQs (`FAQ-*`) were authored directly by the research team. They do not duplicate or reflect confidential terms of any specific commercial enterprise.

---

## 4. Responsible Vulnerability Disclosure

This work analyzes structural vulnerabilities in naive persistent memory architectures (specifically, unkeyed hash chain rewrites and single-database rollback poisoning, as demonstrated in `tests/test_trusted_version_gap.py`).

Because these vulnerabilities stem from architectural omissions in general long-term RAG agent design rather than zero-day vulnerabilities in a specific vendor product, our documentation emphasizes constructive cryptographic safeguards (Ed25519 commit signing, independent witness anchoring, and fail-closed retrieval verification) to elevate security across the agentic AI software ecosystem.
