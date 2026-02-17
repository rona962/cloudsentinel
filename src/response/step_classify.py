"""
CloudSentinel IR - Step 1: Classify
Enriches the alert with additional context and determines response priority.
"""
import json
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(os.environ.get("EVENTS_TABLE", "cloudsentinel-events-dev"))
alerts_table = dynamodb.Table(os.environ.get("ALERTS_TABLE", "cloudsentinel-alerts-dev"))


def handler(event, context):
    """Classify alert severity and enrich with context."""
    detail = event.get("detail", event)

    alert_id = detail.get("alert_id", "unknown")
    severity = detail.get("severity", "MEDIUM")
    rule_name = detail.get("rule_name", "UNKNOWN")
    source_ip = detail.get("source_ip", "N/A")
    user_identity = detail.get("user_identity", "N/A")
    event_ids = detail.get("event_ids", [])

    # Determine priority based on multiple factors
    priority_score = 0
    risk_factors = []

    # Severity scoring
    severity_scores = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}
    priority_score += severity_scores.get(severity, 10)

    # Multi-stage attack bonus
    if "MULTI_STAGE" in rule_name:
        priority_score += 25
        risk_factors.append("Multi-stage attack detected")

    # Root user activity
    if "root" in str(user_identity).lower():
        priority_score += 20
        risk_factors.append("Root user involved")

    # Real CloudTrail events get higher priority than simulated
    description = detail.get("description", "")
    if "cloudtrail_real" in str(detail):
        priority_score += 15
        risk_factors.append("Real AWS activity (not simulated)")

    # Multiple events
    if len(event_ids) > 5:
        priority_score += 10
        risk_factors.append(f"High event volume ({len(event_ids)} events)")

    # Determine response mode
    if priority_score >= 60:
        response_mode = "emergency"
        response_sla = "5 minutes"
    elif priority_score >= 40:
        response_mode = "urgent"
        response_sla = "15 minutes"
    else:
        response_mode = "standard"
        response_sla = "1 hour"

    classification = {
        "alert_id": alert_id,
        "severity": severity,
        "priority_score": priority_score,
        "risk_factors": risk_factors,
        "response_mode": response_mode,
        "response_sla": response_sla,
        "rule_name": rule_name,
        "source_ip": source_ip,
        "user_identity": user_identity,
        "event_count": len(event_ids),
        "classified_at": datetime.now(timezone.utc).isoformat(),
        "step": "CLASSIFY",
    }

    print(f"[IR-Classify] Alert {alert_id}: score={priority_score}, mode={response_mode}, factors={risk_factors}")

    return classification
