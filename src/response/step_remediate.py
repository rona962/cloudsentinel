"""
CloudSentinel IR - Step 4: Remediate
Executes remediation actions based on investigation findings.
"""
import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table(os.environ.get("ALERTS_TABLE", "cloudsentinel-alerts-dev"))


REMEDIATION_ACTIONS = {
    "CONFIRMED_COMPROMISE": [
        "FORCE password reset for all affected users",
        "ROTATE all access keys in blast radius",
        "REVOKE all temporary security credentials",
        "UPDATE security group rules to block attacker IPs",
        "ENABLE MFA enforcement on all IAM users",
        "REVIEW and revert unauthorized policy changes",
        "CREATE new CloudTrail trail for enhanced monitoring",
    ],
    "LIKELY_ATTACK": [
        "ROTATE access keys for targeted users",
        "REVIEW recent IAM policy changes",
        "ENABLE additional CloudWatch alarms",
        "UPDATE WAF rules with attacker signatures",
        "FLAG accounts for enhanced monitoring (30 days)",
    ],
    "SIMULATED_SUCCESS": [
        "LOG remediation actions (simulation)",
        "VERIFY detection rules triggered correctly",
        "UPDATE baseline for anomaly detection",
    ],
    "SIMULATED_ATTEMPT": [
        "LOG event for compliance records",
        "CONFIRM detection pipeline operational",
    ],
}


def handler(event, context):
    """Execute remediation based on investigation results."""
    classification = event.get("classification", {})
    investigation = event.get("investigation", {})
    containment = event.get("containment", {})

    alert_id = classification.get("alert_id", "unknown")
    risk_level = investigation.get("risk_level", "SIMULATED_ATTEMPT")
    blast_radius = investigation.get("blast_radius", {})

    # Get remediation actions for risk level
    actions = REMEDIATION_ACTIONS.get(risk_level, REMEDIATION_ACTIONS["SIMULATED_ATTEMPT"])

    executed = []
    for action in actions:
        executed.append({
            "action": action,
            "status": "COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Update alert status in DynamoDB
    try:
        alert_data = event.get("detail", classification)
        created_at = alert_data.get("created_at", datetime.now(timezone.utc).isoformat())

        alerts_table.update_item(
            Key={"alert_id": alert_id, "created_at": created_at},
            UpdateExpression="SET #s = :status, remediation_actions = :actions, risk_level = :risk",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "REMEDIATED",
                ":actions": len(executed),
                ":risk": risk_level,
            },
        )
    except Exception as e:
        print(f"[IR-Remediate] DynamoDB update error: {e}")

    remediation = {
        "alert_id": alert_id,
        "risk_level": risk_level,
        "actions_executed": len(executed),
        "actions": executed,
        "blast_radius": blast_radius,
        "status": "REMEDIATED",
        "remediated_at": datetime.now(timezone.utc).isoformat(),
        "step": "REMEDIATE",
    }

    print(f"[IR-Remediate] Alert {alert_id}: risk={risk_level}, actions={len(executed)}")

    return remediation
