"""
CloudSentinel - Correlation Engine
Processes DynamoDB Stream events and applies detection rules to generate alerts.
Triggered by new items in SecurityEventsTable.
"""
import json
import os
import uuid
import time
from datetime import datetime, timezone
from collections import defaultdict
from decimal import Decimal

import boto3

dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(os.environ["EVENTS_TABLE"])
alerts_table = dynamodb.Table(os.environ["ALERTS_TABLE"])
sns_client = boto3.client("sns")
eventbridge = boto3.client("events")

ALERT_TOPIC = os.environ["ALERT_TOPIC"]


# ── Detection Rules ──────────────────────────────────────────────

def rule_brute_force_threshold(events: list[dict]) -> dict | None:
    """
    RULE: Multiple failed logins from same IP within batch.
    Trigger: 3+ failed logins from same source IP.
    """
    ip_failures = defaultdict(list)
    for e in events:
        if e.get("event_type") == "BRUTE_FORCE" and e.get("outcome") == "failure":
            ip_failures[e["source_ip"]].append(e)

    for ip, failed_events in ip_failures.items():
        if len(failed_events) >= 3:
            return {
                "rule_name": "BRUTE_FORCE_THRESHOLD",
                "severity": "HIGH",
                "title": f"Brute force detected from {ip}",
                "description": (
                    f"{len(failed_events)} failed login attempts from {ip} "
                    f"targeting user(s): {', '.join(set(e['user_identity'] for e in failed_events))}"
                ),
                "source_ip": ip,
                "mitre_technique": "T1110 - Brute Force",
                "event_ids": [e["event_id"] for e in failed_events],
                "recommended_action": "Block IP in NACL, investigate affected accounts",
            }
    return None


def rule_privilege_escalation(events: list[dict]) -> dict | None:
    """
    RULE: IAM policy attachment or role chain detected.
    Trigger: Any PRIVILEGE_ESCALATION event with CRITICAL severity.
    """
    for e in events:
        if e.get("event_type") == "PRIVILEGE_ESCALATION" and e.get("severity") == "CRITICAL":
            return {
                "rule_name": "PRIVILEGE_ESCALATION_CRITICAL",
                "severity": "CRITICAL",
                "title": f"Critical privilege escalation by {e['user_identity']}",
                "description": (
                    f"User {e['user_identity']} performed {e['action']} on {e['resource']}. "
                    f"Details: {e.get('details', {}).get('risk', 'Unknown')}"
                ),
                "source_ip": e["source_ip"],
                "user_identity": e["user_identity"],
                "mitre_technique": e.get("mitre_technique", "T1078"),
                "event_ids": [e["event_id"]],
                "recommended_action": "Revoke user permissions immediately, investigate session",
            }
    return None


def rule_data_exfiltration(events: list[dict]) -> dict | None:
    """
    RULE: Data exfiltration pattern detected.
    Trigger: Mass download or bucket policy change with external access.
    """
    for e in events:
        if e.get("event_type") == "DATA_EXFILTRATION" and e.get("severity") in ("HIGH", "CRITICAL"):
            sub_type = e.get("details", {}).get("sub_type", "unknown")
            return {
                "rule_name": "DATA_EXFILTRATION_DETECTED",
                "severity": "CRITICAL",
                "title": f"Data exfiltration pattern: {sub_type}",
                "description": (
                    f"Exfiltration pattern '{sub_type}' detected. "
                    f"User: {e['user_identity']}, Resource: {e['resource']}"
                ),
                "source_ip": e["source_ip"],
                "user_identity": e["user_identity"],
                "mitre_technique": e.get("mitre_technique", "T1537"),
                "event_ids": [e["event_id"]],
                "recommended_action": "Lock affected S3 buckets, revoke user access, audit data access logs",
            }
    return None


def rule_lateral_movement(events: list[dict]) -> dict | None:
    """
    RULE: Lateral movement across accounts or via IMDS.
    Trigger: External IP using instance credentials OR cross-account from suspicious source.
    """
    for e in events:
        if e.get("event_type") == "LATERAL_MOVEMENT" and e.get("severity") in ("HIGH", "CRITICAL"):
            return {
                "rule_name": "LATERAL_MOVEMENT_DETECTED",
                "severity": "HIGH",
                "title": f"Lateral movement detected: {e.get('details', {}).get('sub_type', 'unknown')}",
                "description": (
                    f"Suspicious lateral movement from {e['source_ip']}. "
                    f"Action: {e['action']} on {e['resource']}"
                ),
                "source_ip": e["source_ip"],
                "user_identity": e["user_identity"],
                "mitre_technique": e.get("mitre_technique", "T1550"),
                "event_ids": [e["event_id"]],
                "recommended_action": "Isolate affected instances, rotate credentials, review trust policies",
            }
    return None


def rule_multi_stage_attack(events: list[dict]) -> dict | None:
    """
    RULE: Multiple attack types in same batch = coordinated attack.
    Trigger: 2+ different event types in same batch.
    """
    event_types = set(e.get("event_type") for e in events if e.get("event_type"))

    if len(event_types) >= 2:
        return {
            "rule_name": "MULTI_STAGE_ATTACK",
            "severity": "CRITICAL",
            "title": f"Multi-stage attack detected: {', '.join(event_types)}",
            "description": (
                f"Coordinated attack involving {len(event_types)} different tactics: "
                f"{', '.join(event_types)}. Total events: {len(events)}"
            ),
            "attack_types": list(event_types),
            "mitre_technique": "Multiple TTPs",
            "event_ids": [e["event_id"] for e in events],
            "recommended_action": "INCIDENT RESPONSE: Activate IR playbook, isolate all affected resources",
        }
    return None


# All detection rules
DETECTION_RULES = [
    rule_brute_force_threshold,
    rule_privilege_escalation,
    rule_data_exfiltration,
    rule_lateral_movement,
    rule_multi_stage_attack,
]


# ── Alert generation ─────────────────────────────────────────────

def create_alert(rule_result: dict) -> dict:
    """Write alert to DynamoDB and publish to EventBridge + SNS."""
    now = datetime.now(timezone.utc)
    alert_id = str(uuid.uuid4())

    alert = {
        "alert_id": alert_id,
        "created_at": now.isoformat(),
        "severity": rule_result["severity"],
        "rule_name": rule_result["rule_name"],
        "title": rule_result["title"],
        "description": rule_result["description"],
        "mitre_technique": rule_result.get("mitre_technique", "Unknown"),
        "recommended_action": rule_result.get("recommended_action", "Investigate"),
        "event_ids": rule_result.get("event_ids", []),
        "source_ip": rule_result.get("source_ip", "N/A"),
        "user_identity": rule_result.get("user_identity", "N/A"),
        "status": "OPEN",
        "ttl": int(time.time()) + 86400 * 30,
    }

    # Store in DynamoDB
    item = json.loads(json.dumps(alert), parse_float=Decimal)
    alerts_table.put_item(Item=item)

    # Publish to EventBridge (triggers AutoResponder for HIGH/CRITICAL)
    eventbridge.put_events(
        Entries=[{
            "Source": "cloudsentinel.detection",
            "DetailType": "SecurityAlert",
            "Detail": json.dumps({
                "alert_id": alert_id,
                "severity": alert["severity"],
                "rule_name": alert["rule_name"],
                "title": alert["title"],
                "description": alert["description"],
                "recommended_action": alert["recommended_action"],
            }),
        }]
    )

    # Publish to SNS for email notification
    sns_client.publish(
        TopicArn=ALERT_TOPIC,
        Subject=f"[CloudSentinel] {alert['severity']}: {alert['title']}",
        Message=json.dumps(alert, indent=2, default=str),
    )

    return alert


# ── Lambda Handler ───────────────────────────────────────────────

def handler(event, context):
    """
    Process DynamoDB Stream records.
    Extracts new security events, applies detection rules, generates alerts.
    """
    # Parse DynamoDB Stream records into security events
    new_events = []
    for record in event.get("Records", []):
        if record["eventName"] != "INSERT":
            continue

        # DynamoDB Stream format: NewImage with typed values
        image = record["dynamodb"].get("NewImage", {})
        parsed = _deserialize_dynamodb(image)

        # Only process security events (not alerts or other items)
        if parsed.get("event_type"):
            new_events.append(parsed)

    if not new_events:
        return {"statusCode": 200, "alerts_generated": 0}

    # Apply detection rules
    alerts = []
    for rule in DETECTION_RULES:
        result = rule(new_events)
        if result:
            alert = create_alert(result)
            alerts.append(alert)

    return {
        "statusCode": 200,
        "events_processed": len(new_events),
        "alerts_generated": len(alerts),
        "alert_severities": [a["severity"] for a in alerts],
    }


def _deserialize_dynamodb(image: dict) -> dict:
    """Simple DynamoDB Stream image deserializer."""
    result = {}
    for key, typed_value in image.items():
        for type_key, value in typed_value.items():
            if type_key == "S":
                result[key] = value
            elif type_key == "N":
                result[key] = float(value) if "." in value else int(value)
            elif type_key == "BOOL":
                result[key] = value
            elif type_key == "M":
                result[key] = _deserialize_dynamodb(value)
            elif type_key == "L":
                result[key] = [
                    list(v.values())[0] for v in value
                ]
            elif type_key == "NULL":
                result[key] = None
    return result
