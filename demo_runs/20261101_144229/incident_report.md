# AegisMem Incident Forensics Report — REPORT-sess-inc-d72185c6
**Generated:** 2026-11-01T14:51:14.510835+00:00  
**Database Source:** PostgreSQL aegismem_demo (Read-Back Audit)  
**Session ID:** `sess-inc-d72185c6`  

---

## 1. Threat Actor & Network Telemetry
- **Actor Identity:** `kali-attacker`
- **Source IP / Port:** `172.21.0.4:50394`
- **Entry Point Ingress:** `POST /attacker/memory/write`

## 2. Reconnaissance vs. Modifications Audit
### Memories Read (2)
| Memory ID | Version | Endpoint | Source IP | Access Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| `POLICY-001` | v1 | `/api/memories/POLICY-001` | `172.21.0.4` | 2026-11-01T14:42:33.593801+00:00 |
| `SOP-003` | v1 | `/api/memories/SOP-003` | `172.21.0.4` | 2026-11-01T14:42:33.836691+00:00 |

### Memories Modified (1)
#### Target: `POLICY-001` (Attack ID: `ATK-B6619617406F`)
- **Original Version:** v1 $\to$ **Tampered Target Version:** v2
- **Restored Active Version:** v3 (Status: `active`, Trust Score: `1.0`)

**Unified Content Diff:**
```diff
--- POLICY-001_v1
+++ POLICY-001_v2
@@ -1 +1 @@
-Customers may request refunds within 30 calendar days of purchase.
+Customer refunds are permitted within 180 calendar days of the transaction, subject to eligibility verification.
```

## 3. Cryptographic Detection & SOC Alerts
| Alert ID | Target Memory | Severity | Score | Timestamp | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SOC-B93E9B1D31A7` | `POLICY-001` | **CRITICAL** | 85.0 | 2026-11-01T14:42:34.227043+00:00 | OPEN |
| `SOC-E786EEA7EC02` | `POLICY-001` | **HIGH** | 70.0 | 2026-11-01T14:42:34.830126+00:00 | OPEN |

## 4. TCRP Recovery & State Restoration
| Memory ID | Action Selected | Cost | Restored Version | Status | Validation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POLICY-001` | **ROLLBACK** | 0.1295 | vNone | `completed` | `None` |
  - *Candidate Costs Evaluated:* `{"DELETE": 0.14250000000000002, "QUARANTINE": 0.30174999999999996, "RETAIN": 1.0, "ROLLBACK": 0.1295}`
| `POLICY-001` | **ROLLBACK** | N/A | v3 | `partial` | `PARTIAL` |

## 5. Chronological Incident Timeline
| Stage | Timestamp (UTC) | Event Detail |
| :--- | :--- | :--- |
| `RECONNAISSANCE_READ` | 2026-11-01T14:42:33.593801+00:00 | Attacker kali-attacker read POLICY-001 v1 via /api/memories/POLICY-001 |
| `RECONNAISSANCE_READ` | 2026-11-01T14:42:33.836691+00:00 | Attacker kali-attacker read SOP-003 v1 via /api/memories/SOP-003 |
| `UNAUTHORIZED_WRITE` | 2026-11-01T14:42:34.195436+00:00 | Attacker kali-attacker wrote unauthorized modification to POLICY-001 via /attacker/memory/write |
| `DETECTION_ALERT` | 2026-11-01T14:42:34.227043+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-B93E9B1D31A7, Severity: CRITICAL) |
| `DETECTION_ALERT` | 2026-11-01T14:42:34.830126+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-E786EEA7EC02, Severity: HIGH) |
| `TCRP_RECOVERY` | 2026-11-01T14:42:35.017699+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T14:42:35.268096+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to v3 (PARTIAL) |

## 6. Telemetry & Performance Measurements
- **Dwell Time ($T_{detect} - T_{write}$):** 31.61 ms
- **Recovery Execution Duration ($T_{recover} - T_{detect}$):** 1041.05 ms
- **Total Incident Lifecycle Duration:** 1072.66 ms
- **Exposure Window:** 0 wrong answers served (**ZERO EXPOSURE**)
