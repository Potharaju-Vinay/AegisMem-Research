
from core.soc.models import SOCAlert


def get_alerts(session, severity=None, status=None, limit=100):
    query = session.query(SOCAlert)

    if severity:
        query = query.filter(SOCAlert.severity == severity.upper())

    if status:
        query = query.filter(SOCAlert.status == status.upper())

    return (
        query.order_by(SOCAlert.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )


def get_alert_summary(session):
    alerts = session.query(SOCAlert).all()

    return {
        "total": len(alerts),
        "open": sum(a.status == "OPEN" for a in alerts),
        "critical": sum(
            a.severity == "CRITICAL" and a.status == "OPEN"
            for a in alerts
        ),
        "high": sum(
            a.severity == "HIGH" and a.status == "OPEN"
            for a in alerts
        ),
        "medium": sum(
            a.severity == "MEDIUM" and a.status == "OPEN"
            for a in alerts
        ),
        "low": sum(
            a.severity == "LOW" and a.status == "OPEN"
            for a in alerts
        ),
    }
    
def update_alert_status(session, alert_id, new_status):
    allowed_statuses = {"OPEN", "ACKNOWLEDGED", "RESOLVED"}

    status = new_status.upper()

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid status. Choose one of: {', '.join(sorted(allowed_statuses))}"
        )

    alert = session.query(SOCAlert).filter_by(
        alert_id=alert_id
    ).first()

    if alert is None:
        return None

    alert.status = status
    session.commit()
    session.refresh(alert)

    return alert
