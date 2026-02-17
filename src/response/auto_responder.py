"""
CloudSentinel - Automated Response Engine
Receives critical/high alerts from EventBridge and executes response playbooks.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table(os.environ["ALERTS_TABLE"])
s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

INCIDENTS_BUCKET = os.environ["INCIDENTS_BUCKET"]
ALERT_TOPIC = os.environ["ALERT_TOPIC"]


# ── Response Playbooks ───────────────────────────────────────────

PLAYBOOKS = {
    "BRUTE_FORCE_THRESHOLD": {
        "actions": [
            "BLOCK_IP: Add source IP to NACL deny list",
            "DISABLE_USER: Temporarily disable targeted user accounts",
            "FORCE_MFA: Require MFA reset for affected accounts",
            "LOG: Generate detailed incident timeline",
        ],
        "auto_remediate": True,
    },
    "PRIVILEGE_ESCALATION_CRITICAL": {
        "actions": [
            "REVOKE_PERMISSIONS: Remove attached admin policies",
            "INVALIDATE_SESSIONS: Revoke all active sessions for user",
            "SNAPSHOT: Capture current IAM state for forensics",
            "NOTIFY_SECURITY: Page security team immediately",
            "LOG: Generate incident report with full API call history",
        ],
        "auto_remediate": True,
    },
    "DATA_EXFILTRATION_DETECTED": {
        "actions": [
            "LOCK_BUCKET: Set bucket policy to deny all external access",
            "REVOKE_ACCESS: Remove user permissions to affected buckets",
            "ENABLE_LOGGING: Ensure S3 access logging is enabled",
            "QUARANTINE: Move affected data to quarantine bucket",
            "LOG: Generate data access report",
        ],
        "auto_remediate": True,
    },
    "LATERAL_MOVEMENT_DETECTED": {
        "actions": [
            "ISOLATE_INSTANCE: Remove instance from security groups",
            "ROTATE_CREDENTIALS: Force credential rotation for affected roles",
            "REVIEW_TRUST: Audit cross-account trust policies",
            "LOG: Generate lateral movement timeline",
        ],
        "auto_remediate": True,
    },
    "MULTI_STAGE_ATTACK": {
        "actions": [
            "FULL_LOCKDOWN: Activate emergency response protocol",
            "ISOLATE_ALL: Network-isolate all affected resources",
            "REVOKE_ALL: Revoke all sessions for involved identities",
            "FORENSIC_SNAPSHOT: Capture state of all affected resources",
            "ESCALATE: Page incident commander and security leadership",
            "LOG: Generate comprehensive incident report",
        ],
        "auto_remediate": True,
    },
}


def execute_playbook(alert: dict) -> dict:
    """
    Execute the response playbook for a given alert.
    In a real SIEM, this would make actual AWS API calls.
    Here we simulate and log the actions.
    """
    rule_name = alert.get("rule_name", "UNKNOWN")
    playbook = PLAYBOOKS.get(rule_name, {
        "actions": ["LOG: Unknown alert type - manual investigation required"],
        "auto_remediate": False,
    })

    executed_actions = []
    for action in playbook["actions"]:
        action_result = {
            "action": action,
            "status": "SIMULATED",  # In production: "EXECUTED"
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Simulate action execution
        if action.startswith("BLOCK_IP"):
            action_result["details"] = {
                "ip": alert.get("source_ip", "unknown"),
                "nacl_rule_number": 50,
                "nacl_id": "acl-0abc123def456",
            }
        elif action.startswith("REVOKE_PERMISSIONS") or action.startswith("REVOKE_ACCESS"):
            action_result["details"] = {
                "user": alert.get("user_identity", "unknown"),
                "policies_detached": ["AdministratorAccess"],
            }
        elif action.startswith("INVALIDATE_SESSIONS") or action.startswith("REVOKE_ALL"):
            action_result["details"] = {
                "user": alert.get("user_identity", "unknown"),
                "sessions_revoked": 3,
            }
        elif action.startswith("LOG"):
            action_result["details"] = {
                "report_location": f"s3://{INCIDENTS_BUCKET}/incidents/{alert.get('alert_id', 'unknown')}.json",
            }

        executed_actions.append(action_result)

    return {
        "playbook": rule_name,
        "auto_remediate": playbook["auto_remediate"],
        "actions_executed": len(executed_actions),
        "actions": executed_actions,
    }


def generate_incident_report(alert: dict, response_result: dict) -> str:
    """Generate a JSON incident report and store in S3."""
    alert_id = alert.get("alert_id", str(uuid.uuid4()))

    report = {
        "incident_id": f"INC-{alert_id[:8].upper()}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
        "response": response_result,
        "timeline": [
            {
                "time": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "event": "Attack detected",
            },
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "event": "Automated response executed",
            },
        ],
        "status": "CONTAINED" if response_result["auto_remediate"] else "INVESTIGATING",
        "next_steps": [
            "Review incident report",
            "Verify automated remediation was effective",
            "Conduct root cause analysis",
            "Update detection rules if needed",
        ],
    }

    # Store in S3
    report_key = f"incidents/{alert_id}.json"
    s3_client.put_object(
        Bucket=INCIDENTS_BUCKET,
        Key=report_key,
        Body=json.dumps(report, indent=2, default=str),
        ContentType="application/json",
    )

    return f"s3://{INCIDENTS_BUCKET}/{report_key}"


# ── Lambda Handler ───────────────────────────────────────────────

def handler(event, context):
    """
    Process EventBridge events for critical/high alerts.
    Executes appropriate playbook and generates incident report.
    """
    # EventBridge event structure
    detail = event.get("detail", {})
    alert_id = detail.get("alert_id", "unknown")
    severity = detail.get("severity", "UNKNOWN")

    print(f"[AutoResponder] Processing {severity} alert: {detail.get('title', 'Unknown')}")

    # Execute playbook
    response_result = execute_playbook(detail)

    # Generate incident report
    report_location = generate_incident_report(detail, response_result)

    # Update alert status in DynamoDB
    try:
        alerts_table.update_item(
            Key={
                "alert_id": alert_id,
                "created_at": detail.get("created_at", datetime.now(timezone.utc).isoformat()),
            },
            UpdateExpression="SET #s = :status, response_actions = :actions, report_location = :report",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "CONTAINED",
                ":actions": response_result["actions_executed"],
                ":report": report_location,
            },
            ConditionExpression="attribute_exists(alert_id)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        # Alert doesn't exist yet (race condition) — write full record
        from decimal import Decimal
        full_alert = {
            "alert_id": alert_id,
            "created_at": detail.get("created_at", datetime.now(timezone.utc).isoformat()),
            "severity": severity,
            "rule_name": detail.get("rule_name", "UNKNOWN"),
            "title": detail.get("title", "Auto-responded alert"),
            "description": detail.get("description", ""),
            "recommended_action": detail.get("recommended_action", ""),
            "status": "CONTAINED",
            "response_actions": response_result["actions_executed"],
            "report_location": report_location,
            "ttl": int(time.time()) + 86400 * 30,
        }
        item = json.loads(json.dumps(full_alert), parse_float=Decimal)
        alerts_table.put_item(Item=item)
    except Exception as e:
        print(f"[AutoResponder] Warning: Could not update alert status: {e}")

    # Send response notification
    sns_client.publish(
        TopicArn=ALERT_TOPIC,
        Subject=f"[CloudSentinel] RESPONSE: {detail.get('title', 'Unknown')}",
        Message=json.dumps({
            "alert_id": alert_id,
            "severity": severity,
            "status": "CONTAINED",
            "playbook": response_result["playbook"],
            "actions_executed": response_result["actions_executed"],
            "report": report_location,
        }, indent=2),
    )

    return {
        "statusCode": 200,
        "alert_id": alert_id,
        "severity": severity,
        "status": "CONTAINED",
        "actions_executed": response_result["actions_executed"],
        "report_location": report_location,
    }
