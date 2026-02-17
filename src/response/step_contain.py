"""
CloudSentinel IR - Step 2: Contain
Executes containment actions based on severity and mode.
"""
import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table(os.environ.get("ALERTS_TABLE", "cloudsentinel-alerts-dev"))


CONTAINMENT_PLAYBOOKS = {
    "emergency": {
        "BRUTE_FORCE": [
            "BLOCK source IP at WAF/Security Group",
            "DISABLE compromised user account",
            "REVOKE all active sessions",
            "ENABLE enhanced CloudTrail logging",
        ],
        "PRIVILEGE_ESCALATION": [
            "DETACH all newly attached policies",
            "REVOKE temporary credentials",
            "DISABLE affected IAM user/role",
            "SNAPSHOT affected resources for forensics",
        ],
        "DATA_EXFILTRATION": [
            "REVERT bucket policy to last known good",
            "BLOCK public access on affected buckets",
            "REVOKE cross-account access",
            "ENABLE S3 access logging",
        ],
        "LATERAL_MOVEMENT": [
            "ISOLATE affected EC2 instances",
            "REVOKE assumed role sessions",
            "BLOCK cross-account trust relationships",
            "ROTATE all credentials in blast radius",
        ],
        "MULTI_STAGE_ATTACK": [
            "ACTIVATE full incident response team",
            "ISOLATE all affected resources",
            "REVOKE all suspicious sessions",
            "BLOCK attacker IP ranges",
            "PRESERVE evidence in isolated environment",
            "ENABLE maximum logging on all services",
        ],
    },
    "standard": {
        "DEFAULT": [
            "LOG containment action initiated",
            "FLAG user for enhanced monitoring",
            "CREATE investigation ticket",
        ],
    },
}


def handler(event, context):
    """Execute containment actions."""
    alert = event.get("alert", event.get("detail", {}))
    classification = event.get("classification", {})
    mode = event.get("mode", classification.get("response_mode", "standard"))

    alert_id = classification.get("alert_id", alert.get("alert_id", "unknown"))
    rule_name = classification.get("rule_name", alert.get("rule_name", "UNKNOWN"))
    severity = classification.get("severity", alert.get("severity", "MEDIUM"))

    # Get attack type from rule name
    attack_type = "DEFAULT"
    for t in ["BRUTE_FORCE", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION", "LATERAL_MOVEMENT", "MULTI_STAGE"]:
        if t in rule_name:
            attack_type = t
            break

    # Get playbook
    if mode == "emergency":
        actions = CONTAINMENT_PLAYBOOKS["emergency"].get(
            attack_type,
            CONTAINMENT_PLAYBOOKS["emergency"].get("PRIVILEGE_ESCALATION", [])
        )
    else:
        actions = CONTAINMENT_PLAYBOOKS["standard"]["DEFAULT"]

    # Simulate executing each action
    executed_actions = []
    for action in actions:
        executed_actions.append({
            "action": action,
            "status": "EXECUTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    containment = {
        "alert_id": alert_id,
        "mode": mode,
        "attack_type": attack_type,
        "actions_executed": len(executed_actions),
        "actions": executed_actions,
        "status": "CONTAINED",
        "contained_at": datetime.now(timezone.utc).isoformat(),
        "step": "CONTAIN",
    }

    print(f"[IR-Contain] Alert {alert_id}: mode={mode}, actions={len(executed_actions)}")

    return containment
