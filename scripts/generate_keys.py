#!/usr/bin/env python3
"""
AegisMem Cryptographic Key Generator (Milestone F4)
Generates fresh Ed25519 keypairs for:
- Integrity Anchor Witness
- Owner Update Approval
- Owner Request Signature
- TCRP Recovery Attestation

Segregates keys strictly into isolated directories for single-service container mounts:
- security/keys: Master key storage (owner private keys stay strictly on host)
- security/public_keys: Public keys ONLY (for gateway, detector, support-agent)
- security/anchor_keys: Anchor private key + public keys (for anchor witness only)
- security/recovery_keys: Recovery private key + public keys (for recovery resolver only)
"""
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEY_DIR = Path("security/keys")
PUB_DIR = Path("security/public_keys")
ANCHOR_DIR = Path("security/anchor_keys")
REC_DIR = Path("security/recovery_keys")


def main():
    for d in [KEY_DIR, PUB_DIR, ANCHOR_DIR, REC_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    
    # 1. Integrity Anchor Keypair
    priv_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = priv_a.public_key()
    priv_a_bytes = priv_a.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_a_bytes = pub_a.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    
    (KEY_DIR / "integrity_anchor_private.pem").write_bytes(priv_a_bytes)
    (KEY_DIR / "integrity_anchor_public.pem").write_bytes(pub_a_bytes)
    (PUB_DIR / "integrity_anchor_public.pem").write_bytes(pub_a_bytes)
    (ANCHOR_DIR / "integrity_anchor_private.pem").write_bytes(priv_a_bytes)
    (ANCHOR_DIR / "integrity_anchor_public.pem").write_bytes(pub_a_bytes)
    (REC_DIR / "integrity_anchor_public.pem").write_bytes(pub_a_bytes)
    print("Generated: integrity_anchor_private.pem, integrity_anchor_public.pem")

    # 2. Owner Approval Keypair
    priv_o = ed25519.Ed25519PrivateKey.generate()
    pub_o = priv_o.public_key()
    priv_o_bytes = priv_o.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_o_bytes = pub_o.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    
    (KEY_DIR / "owner_private_key.pem").write_bytes(priv_o_bytes)
    (KEY_DIR / "owner_public_key.pem").write_bytes(pub_o_bytes)
    (PUB_DIR / "owner_public_key.pem").write_bytes(pub_o_bytes)
    (ANCHOR_DIR / "owner_public_key.pem").write_bytes(pub_o_bytes)
    (REC_DIR / "owner_public_key.pem").write_bytes(pub_o_bytes)
    print("Generated: owner_private_key.pem, owner_public_key.pem")

    # 3. Owner Request Keypair
    priv_r = ed25519.Ed25519PrivateKey.generate()
    pub_r = priv_r.public_key()
    priv_r_bytes = priv_r.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_r_bytes = pub_r.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    
    (KEY_DIR / "owner_request_private_key.pem").write_bytes(priv_r_bytes)
    (KEY_DIR / "owner_request_public_key.pem").write_bytes(pub_r_bytes)
    (PUB_DIR / "owner_request_public_key.pem").write_bytes(pub_r_bytes)
    (ANCHOR_DIR / "owner_request_public_key.pem").write_bytes(pub_r_bytes)
    (REC_DIR / "owner_request_public_key.pem").write_bytes(pub_r_bytes)
    print("Generated: owner_request_private_key.pem, owner_request_public_key.pem")

    # 4. Recovery Attestation Keypair
    priv_rec = ed25519.Ed25519PrivateKey.generate()
    pub_rec = priv_rec.public_key()
    priv_rec_bytes = priv_rec.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_rec_bytes = pub_rec.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    
    (KEY_DIR / "recovery_attestation_private.pem").write_bytes(priv_rec_bytes)
    (KEY_DIR / "recovery_attestation_public.pem").write_bytes(pub_rec_bytes)
    (PUB_DIR / "recovery_attestation_public.pem").write_bytes(pub_rec_bytes)
    (REC_DIR / "recovery_attestation_private.pem").write_bytes(priv_rec_bytes)
    (REC_DIR / "recovery_attestation_public.pem").write_bytes(pub_rec_bytes)
    print("Generated: recovery_attestation_private.pem, recovery_attestation_public.pem")


if __name__ == "__main__":
    main()
