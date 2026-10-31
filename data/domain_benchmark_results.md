# AegisMem Domain Benchmark: Baseline Comparison
**Evaluation Replications:** 5 Independent Seeds | **Target Domain:** Enterprise AI Customer Support

| Baseline | Attack Success Rate (ASR %) | Recovery Accuracy (%) | False Rollback Rate (FRR %) | Exposure (Wrong Answers) |
|---|---|---|---|---|
| retain_only | 81.82% +/- 0.0% | 50.0% +/- 0.0% | 0.0% +/- 0.0% | 9 +/- 0.0 |
| rule_based_rollback | 72.73% +/- 0.0% | 80.0% +/- 0.0% | 10.0% +/- 0.0% | 8 +/- 0.0 |
| detection_only | 81.82% +/- 0.0% | 0.0% +/- 0.0% | 0.0% +/- 0.0% | 9 +/- 0.0 |
| tcrp_no_anchor | 9.09% +/- 0.0% | 90.0% +/- 0.0% | 0.0% +/- 0.0% | 1 +/- 0.0 |
| **AegisMem (Full System)** | **0.0% +/- 0.0%** | **100.0% +/- 0.0%** | **0.0% +/- 0.0%** | **0 +/- 0.0** |

### Metric Definitions & Acceptance Criteria (Part D):
- **Attack Success Rate (ASR):** Percentage of queries served under attack that returned corrupted/fraudulent policy content. Lower is better. AegisMem ReadPathGate ensures 0.0% ASR.
- **Recovery Accuracy:** Percentage of recovery incidents that correctly restored the authentic ground-truth memory version without accepting tampered ancestors or history rewrites. AegisMem Trust Anchor Ladder achieves 100.0%.
- **False Rollback Rate (FRR):** Percentage of >= 100 legitimate signed staff updates that were erroneously rejected or rolled back. Acceptance: strictly 0.0% false rollbacks.
- **Exposure Window:** Total count of wrong answers served to users during an active incident. AegisMem verify-on-read read-path gate strictly bounds this to 0 wrong answers.