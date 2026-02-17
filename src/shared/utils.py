"""
CloudSentinel - Shared utilities and MITRE ATT&CK mappings.
"""
import os
import uuid
import json
import time
import random
from datetime import datetime, timezone
from decimal import Decimal

import boto3

# ── DynamoDB helper ──────────────────────────────────────────────

_events_table = None
_alerts_table = None


def get_events_table():
    global _events_table
    if _events_table is None:
        dynamodb = boto3.resource("dynamodb")
        _events_table = dynamodb.Table(os.environ["EVENTS_TABLE"])
    return _events_table


def get_alerts_table():
    global _alerts_table
    if _alerts_table is None:
        dynamodb = boto3.resource("dynamodb")
        _alerts_table = dynamodb.Table(os.environ["ALERTS_TABLE"])
    return _alerts_table


# ── Event builder ────────────────────────────────────────────────

def create_security_event(
    event_type: str,
    source_ip: str,
    user_identity: str,
    action: str,
    resource: str,
    outcome: str,  # "success" | "failure"
    severity: str,  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    mitre_tactic: str,
    mitre_technique: str,
    details: dict | None = None,
) -> dict:
    """Create a standardised security event and write it to DynamoDB."""
    now = datetime.now(timezone.utc)
    event_id = str(uuid.uuid4())

    event = {
        "pk": f"EVENT#{now.strftime('%Y-%m-%d')}",
        "sk": f"{now.isoformat()}#{event_id}",
        "gsi1pk": f"TYPE#{event_type}",
        "gsi1sk": now.isoformat(),
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": now.isoformat(),
        "source_ip": source_ip,
        "user_identity": user_identity,
        "action": action,
        "resource": resource,
        "outcome": outcome,
        "severity": severity,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "details": json.loads(json.dumps(details or {}, default=str)),
        "ttl": int(time.time()) + 86400 * 30,  # 30 days
    }

    table = get_events_table()
    # DynamoDB needs Decimal instead of float
    item = json.loads(json.dumps(event), parse_float=Decimal)
    table.put_item(Item=item)
    return event


# ── MITRE ATT&CK Reference (subset) ─────────────────────────────

MITRE = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1078 - Valid Accounts",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1537 - Transfer Data to Cloud Account",
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "technique": "T1550 - Use Alternate Authentication Material",
    },
    "iam_manipulation": {
        "tactic": "Persistence",
        "technique": "T1098 - Account Manipulation",
    },
}

# ── Fake data generators ────────────────────────────────────────

SUSPICIOUS_IPS = [
    "198.51.100.23",   # Known bad actor (RFC 5737 test range)
    "203.0.113.42",    # Simulated C2 server
    "192.0.2.100",     # Simulated scanner
    "198.51.100.77",   # Simulated botnet node
    "203.0.113.199",   # Simulated exfil endpoint
]

INTERNAL_IPS = [
    "10.0.1.15",
    "10.0.2.30",
    "10.0.3.45",
    "172.16.0.10",
    "172.16.1.20",
]

USERNAMES = [
    "admin",
    "root",
    "deploy-bot",
    "jane.doe",
    "john.smith",
    "svc-backup",
    "dev-intern",
    "ci-pipeline",
]

AWS_RESOURCES = [
    "arn:aws:s3:::company-secrets-bucket",
    "arn:aws:s3:::financial-reports-2025",
    "arn:aws:iam::123456789012:role/AdminRole",
    "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
    "arn:aws:rds:us-east-1:123456789012:db:production-db",
]


def random_ip(suspicious: bool = True) -> str:
    return random.choice(SUSPICIOUS_IPS if suspicious else INTERNAL_IPS)


def random_username() -> str:
    return random.choice(USERNAMES)


def random_resource() -> str:
    return random.choice(AWS_RESOURCES)
