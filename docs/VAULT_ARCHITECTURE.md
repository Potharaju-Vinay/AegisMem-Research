# AegisMem Trust Vault Architecture & Access Control Specification (Milestone F4)

## 1. Authoritative Vault Definition
In AegisMem, the **Authoritative Trust Vault** consists of two cryptographically synchronized components:
1. **Network-Segmented PostgreSQL Vault Database (`vault-db`)**: Operates on the strictly air-gapped `vault-net` (internal, no external egress or port mappings).
2. **Cryptographic Checkpoint Vault Store (`security/trust_vault/`)**: Houses cryptographically signed version snapshots (`.vault.json`) containing historical state, owner approval signatures, and Ed25519 hash chain proofs.

The Trust Vault is the **authoritative ground truth** for all memory records. If the primary operational database (`memory-db`) is compromised by an adversary, the Trust Vault provides the tamper-evident baseline required for deterministic rollback and self-healing.

---

## 2. Write and Read Access Matrix

| Service | Network Access | Trust Vault Directory (`security/trust_vault`) | Vault DB (`vault-db`) | Read / Write Authority |
| :--- | :--- | :--- | :--- | :--- |
| **`aegismem-recovery`** | `vault-net`, `data-net`, `anchor-net` | **Read/Write** (`/app/security/trust_vault`) | **Read/Write** (`postgresql://.../aegismem_vault`) | **Authoritative Vault Writer & Resolver** (Performs TCRP restoration and checkpointing) |
| **`aegismem-gateway`** | `public-net`, `data-net`, `anchor-net` | **No Mount** (or Read-Only) | **No Network Route** (Blocked by `vault-net` isolation) | **Zero Vault Access** (Reads/writes live operational `memory-db` only) |
| **`aegismem-detector`** | `data-net` | **No Mount** (or Read-Only) | **No Network Route** (Blocked by `vault-net` isolation) | **Zero Vault Access** (Monitors live `memory-db` for anomalies) |
| **`anchor`** | `anchor-net` | **No Mount** | **No Network Route** | **Anchor Witness Only** (Authoritative manifest signing) |
| **`attacker`** | `public-net` | **No Mount** | **No Network Route** (Blocked by Docker network segmentation) | **Adversary Zone** (Zero access to keys or vault) |

---

## 3. How New Vault Entries Are Written When Gateway is Read-Only
When the gateway receives an authenticated owner update:
1. The gateway verifies the owner's digital signature and registers the nonce.
2. The gateway commits the new revision to `memory-db`.
3. The gateway requests an authoritative witness signature from `anchor:8000` on `anchor-net`, forwarding the owner's cryptographic signature.
4. The authoritative snapshot is persisted to the Trust Vault via the isolated **Recovery Service (`aegismem-recovery`)** or during scheduled cryptographic head checkpointing.
5. In an incident, `aegismem-recovery` connects to `vault-db`, retrieves the last untampered cryptographic snapshot, verifies the anchor signature, and executes TCRP self-healing.

---

## 4. Key Management & Separation of Secrets
- **Owner Private Keys (`owner_private_key.pem`, `owner_request_private_key.pem`)**: Reside **strictly on the host admin workstation**. Never mounted into any container or baked into any image.
- **Anchor Private Key (`integrity_anchor_private.pem`)**: Mounted **read-only exclusively into `anchor`**.
- **Recovery Private Key (`recovery_attestation_private.pem`)**: Mounted **read-only exclusively into `aegismem-recovery`**.
- **Public Keys (`security/public_keys/`)**: Mounted read-only across consuming services (`gateway`, `detector`, `recovery`, `support-agent`).

