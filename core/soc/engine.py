
import uuid

from sqlalchemy.exc import IntegrityError

from core.soc.models import SOCAlert
from core.soc.severity import calculate_severity


def create_soc_alert(session, memory_id, attack_id, attack_type, evidence):
    existing = session.query(SOCAlert).filter_by(
        attack_id=attack_id
    ).first()

    if existing:
        return existing

    result = calculate_severity(
        integrity_compromised=evidence.get("integrity_compromised", False),
        provenance_suspicious=evidence.get("provenance_suspicious", False),
        attack_detected=evidence.get("attack_detected", False),
        unauthorized_access=evidence.get("unauthorized_access", False),
        content_changed=evidence.get("content_changed", False),
        dependency_contamination=evidence.get("dependency_contamination", 0.0),
    )

    alert = SOCAlert(
        alert_id=f"SOC-{uuid.uuid4().hex[:12].upper()}",
        attack_id=attack_id,
        memory_id=memory_id,
        attack_type=attack_type,
        severity=result["severity"],
        severity_score=result["severity_score"],
        evidence_summary="; ".join(result["reasons"])
        or "No evidence signals supplied",
        status="OPEN",
    )

    session.add(alert)

    try:
        session.commit()
        session.refresh(alert)
        print(
            f"\n[AegisMem SOC] ================= ALERT TRIGGERED ================="
            f"\n[AegisMem SOC] Alert ID       : {alert.alert_id}"
            f"\n[AegisMem SOC] Memory ID      : {memory_id}"
            f"\n[AegisMem SOC] Attack ID      : {attack_id}"
            f"\n[AegisMem SOC] Attack Type    : {attack_type}"
            f"\n[AegisMem SOC] Severity       : {result['severity']} (Score: {result['severity_score']})"
            f"\n[AegisMem SOC] Evidence       : {alert.evidence_summary}"
            f"\n[AegisMem SOC] Status         : {alert.status}"
            f"\n[AegisMem SOC] ===================================================\n"
        )
        return alert
    except IntegrityError:
        session.rollback()
        existing = session.query(SOCAlert).filter_by(
            attack_id=attack_id
        ).first()
        if existing:
            return existing
        raise


def create_alert_from_attack(session, attack):
    existing = session.query(SOCAlert).filter_by(
        attack_id=attack.attack_id
    ).first()

    if existing:
        return existing

    integrity_compromised = (
        attack.original_content_hash != attack.observed_content_hash
    )
    content_changed = (
        attack.original_content != attack.modified_content
    )
    
    unauthorized_access = False

    result = calculate_severity(
        integrity_compromised=integrity_compromised,
        provenance_suspicious=(
            "unauthorized" in (attack.mutation_description or "").lower()
        ),
        attack_detected=True,
        unauthorized_access=unauthorized_access,
        content_changed=content_changed,
    )

    alert = SOCAlert(
        alert_id=f"SOC-{uuid.uuid4().hex[:12].upper()}",
        attack_id=attack.attack_id,
        memory_id=attack.memory_id,
        attack_type=attack.attack_type,
        severity=result["severity"],
        severity_score=result["severity_score"],
        evidence_summary="; ".join(result["reasons"])
        or "Attack telemetry recorded",
        status="OPEN",
    )

    session.add(alert)

    try:
        session.commit()
        session.refresh(alert)
        attacker_desc = getattr(attack, "attacker", "external-attacker")
        source_ip_desc = getattr(attack, "source_ip", None) or "network-request"
        print(
            f"\n[AegisMem SOC] ================= ALERT TRIGGERED ================="
            f"\n[AegisMem SOC] Alert ID       : {alert.alert_id}"
            f"\n[AegisMem SOC] Memory ID      : {attack.memory_id}"
            f"\n[AegisMem SOC] Attack ID      : {attack.attack_id}"
            f"\n[AegisMem SOC] Attack Type    : {attack.attack_type}"
            f"\n[AegisMem SOC] Severity       : {result['severity']} (Score: {result['severity_score']})"
            f"\n[AegisMem SOC] Attacker       : {attacker_desc} (IP: {source_ip_desc})"
            f"\n[AegisMem SOC] Evidence       : {alert.evidence_summary}"
            f"\n[AegisMem SOC] Status         : {alert.status}"
            f"\n[AegisMem SOC] ===================================================\n"
        )
        return alert
    except IntegrityError:
        session.rollback()
        existing = session.query(SOCAlert).filter_by(
            attack_id=attack.attack_id
        ).first()
        if existing:
            return existing
        raise
