# AegisMem Incident Forensics Report — REPORT-sess-inc-f2630bba
**Generated:** 2026-11-01T15:02:17.532273+00:00  
**Database Source:** PostgreSQL aegismem_demo (Read-Back Audit)  
**Session ID:** `sess-inc-f2630bba`  

---

## 1. Threat Actor & Network Telemetry
- **Actor Identity:** `kali-attacker`
- **Source IP / Port:** `172.21.0.4:60456`
- **Entry Point Ingress:** `POST /attacker/memory/write`

## 2. Reconnaissance vs. Modifications Audit
### Memories Read (2)
| Memory ID | Version | Endpoint | Source IP | Access Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| `POLICY-001` | v1 | `/api/memories/POLICY-001` | `172.21.0.4` | 2026-11-01T15:02:13.931114+00:00 |
| `SOP-003` | v1 | `/api/memories/SOP-003` | `172.21.0.4` | 2026-11-01T15:02:14.089719+00:00 |

### Memories Modified (1)
#### Target: `POLICY-001` (Attack ID: `ATK-BAC8934326A4`)
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
| `SOC-6B9E8A185D42` | `POLICY-001` | **CRITICAL** | 85.0 | 2026-11-01T15:02:14.411058+00:00 | OPEN |
| `SOC-E844E902CC30` | `POLICY-001` | **HIGH** | 70.0 | 2026-11-01T15:02:14.921153+00:00 | OPEN |

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
| `RECONNAISSANCE_READ` | 2026-11-01T15:02:13.931114+00:00 | Attacker kali-attacker read POLICY-001 v1 via /api/memories/POLICY-001 |
| `RECONNAISSANCE_READ` | 2026-11-01T15:02:14.089719+00:00 | Attacker kali-attacker read SOP-003 v1 via /api/memories/SOP-003 |
| `UNAUTHORIZED_WRITE` | 2026-11-01T15:02:14.378718+00:00 | Attacker kali-attacker wrote unauthorized modification to POLICY-001 via /attacker/memory/write |
| `DETECTION_ALERT` | 2026-11-01T15:02:14.411058+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-6B9E8A185D42, Severity: CRITICAL) |
| `DETECTION_ALERT` | 2026-11-01T15:02:14.921153+00:00 | AegisMem detected compromise on POLICY-001 (Alert SOC-E844E902CC30, Severity: HIGH) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.124548+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.128505+00:00 | TCRP action 'QUARANTINE' executed on POLICY-002: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.132536+00:00 | TCRP action 'QUARANTINE' executed on SOP-003: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.338818+00:00 | TCRP action 'ROLLBACK' executed on POLICY-001: restored to v3 (PARTIAL) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.345318+00:00 | TCRP action 'QUARANTINE' executed on POLICY-002: restored to vNone (None) |
| `TCRP_RECOVERY` | 2026-11-01T15:02:15.353098+00:00 | TCRP action 'QUARANTINE' executed on SOP-003: restored to vNone (None) |

## 6. Telemetry & Performance Measurements
- **Dwell Time ($T_{detect} - T_{write}$):** 32.34 ms
- **Recovery Execution Duration ($T_{recover} - T_{detect}$):** 942.04 ms
- **Total Incident Lifecycle Duration:** 974.38 ms
- **Exposure Window:** 0 wrong answers served (**ZERO EXPOSURE**)
