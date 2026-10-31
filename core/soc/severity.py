def calculate_severity(
    integrity_compromised=False,
    provenance_suspicious=False,
    attack_detected=False,
    unauthorized_access=False,
    content_changed=False,
    dependency_contamination=0.0,
):
    score = 0.0
    reasons = []

    if integrity_compromised:
        score += 30
        reasons.append("Memory integrity compromised")

    if provenance_suspicious:
        score += 20
        reasons.append("Suspicious provenance evidence")

    if attack_detected:
        score += 25
        reasons.append("Attack telemetry detected")

    if unauthorized_access:
        score += 15
        reasons.append("Unauthorized access")

    if content_changed:
        score += 10
        reasons.append("Memory content changed")

    if dependency_contamination > 0:
        impact_score = min(float(dependency_contamination), 1.0) * 20
        score += impact_score
        reasons.append("Dependent memory contamination")

    score = min(score, 100)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "severity": severity,
        "severity_score": round(score, 2),
        "reasons": reasons,
    }