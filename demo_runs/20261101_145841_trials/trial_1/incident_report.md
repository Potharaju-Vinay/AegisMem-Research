# AegisMem Incident Forensics Report — REPORT-sess-inc-9a1f7688
**Generated:** 2026-11-01T14:58:53.781089+00:00  
**Database Source:** PostgreSQL aegismem_demo (Read-Back Audit)  
**Session ID:** `sess-inc-9a1f7688`  

---

## 1. Threat Actor & Network Telemetry
- **Actor Identity:** `kali-attacker`
- **Source IP / Port:** `172.21.0.4:57432`
- **Entry Point Ingress:** `POST /attacker/memory/write`

## 2. Reconnaissance vs. Modifications Audit
### Memories Read (2)
| Memory ID | Version | Endpoint | Source IP | Access Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| `POLICY-001` | v1 | `/api/memories/POLICY-001` | `172.21.0.4` | 2026-11-01T14:58:49.323955+00:00 |
| `SOP-003` | v1 | `/api/memories/SOP-003` | `172.21.0.4` | 2026-11-01T14:58:49.505008+00:00 |

### Memories Modified (1)
#### Target: `POLICY-001` (Attack ID: `ATK-BDEE68B1693E`)
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
| `SOC-676C7DCDD665` | `POLICY-001` | **CRITICAL** | 85.0 | 2026-11-01T14:58:49.898467+00:00 | OPEN |
| `SOC-44AD98BD3EA8` | `POLICY-001` | **HIGH** | 70.0 | 2026-11-01T14:58:50.453649+00:00 | OPEN |

## 4. TCRP Recovery & State Restoration
| Memory ID | Action Selected | Cost | Restored Version | Status | Validation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POLICY-001` | **ROLLBACK** | 0.1043 | vNone | `completed` | `None` |
  - *Candidate Costs Evaluated:* `{"DELETE": 0.3225, "QUARANTINE": 0.35274999999999995, "RETAIN": 1.0, "ROLLBACK": 0.1043}`
| `POLICY-002` | **QUARANTINE** | 0.18 | vNone | `completed` | `None` |
  - *Candidate Costs Evaluated:* `{"DELETE": 0.3975, "QUARANTINE": 0.18, "RETAIN": 0.9, "ROLLBACK": 0.31}`
| `SOP-003` | **QUARANTINE** | 0.29900000000000004 | vNone | `completed` | `None` |
  - *Candidate Costs Evaluated:* `{"DELETE": 0.40650000000000003, "QUARANTINE": 0.29900000000000004, "RETAIN": 0.384, "ROLLBACK": 0.382}`
| `POLICY-001` | **ROLLBACK** | N/A | v3 | `partial` | `PARTIAL` |
| `POLICY-002` | **QUARANTINE** | N/A | vNone | `success` | `None` |
| `SOP-003` | **QUARANTINE** | N/A | vNone | `success` | `None` |

## 5. Chronological Incident Timeline
| Stage | Timestamp (UTC) | Event Detail |
| :--- | :--- | :--- |
| `RECONNAISSANCE_READ` | 2026-11-01T14:58:49.323955+00:00 | Attacker kali-attacker read POLICY-001 v1 via /api/memories/POLICY-001 |
| `RECONNAISSANCE_READ` | 2026-11-01T14:58:49.505008+00:00 | Attacker kali-attacker read SOP-003 v1 via /api/memories/SOP-003 |
| `UNAUTHORIZED_WRITE` | 2026-11-01T14:58:49.867073+00:00 | Attacker kali-attacker wrote unauthorized modification to POLICY-001 via /attacker/memory/write |
| `DETECTION_ALERT` | 2026-11-01T14:58:49.898467+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-676C7DCDD665, Severity: CRITICAL) |
| `DETECTION_ALERT` | 2026-11-01T14:58:50.453649+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-44AD98BD3EA8, Severity: HIGH) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:50.719986+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:50.724725+00:00 | TCRP action 'QUARANTINE' executed on POLICY-002: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:50.730201+00:00 | TCRP action 'QUARANTINE' executed on SOP-003: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:51.059401+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to v3 (PARTIAL) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:51.068594+00:00 | TCRP action 'QUARANTINE' executed on POLICY-002: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T14:58:51.076980+00:00 | TCRP action 'QUARANTINE' executed on SOP-003: restored to vNone (None) |

## 6. Telemetry & Performance Measurements
- **Dwell Time ($T_{detect} - T_{write}$):** 31.39 ms
- **Recovery Execution Duration ($T_{recover} - T_{detect}$):** 1178.51 ms
- **Total Incident Lifecycle Duration:** 1209.91 ms
- **Exposure Window:** 0 wrong answers served (**ZERO EXPOSURE**)
