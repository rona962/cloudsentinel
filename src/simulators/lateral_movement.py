"""
CloudSentinel - Lateral Movement Simulator
MITRE ATT&CK: T1550 - Use Alternate Authentication Material

Simulates patterns:
  1. Cross-account role assumption from unusual source
  2. EC2 instance metadata service (IMDS) abuse
  3. SSM session from unexpected user
"""
import random

from shared.utils import (
    create_security_event,
    MITRE,
    random_ip,
    SUSPICIOUS_IPS,
    INTERNAL_IPS,
)


def generate_cross_account_movement():
    """Role assumed from unusual IP / at unusual time."""
    attacker_ip = random.choice(SUSPICIOUS_IPS)
    compromised_user = random.choice(["ci-pipeline", "deploy-bot"])
    events = []

    # Assume role into production account
    events.append(create_security_event(
        event_type="LATERAL_MOVEMENT",
        source_ip=attacker_ip,
        user_identity=compromised_user,
        action="sts:AssumeRole",
        resource="arn:aws:iam::111222333444:role/CrossAccountAdmin",
        outcome="success",
        severity="HIGH",
        mitre_tactic=MITRE["lateral_movement"]["tactic"],
        mitre_technique=MITRE["lateral_movement"]["technique"],
        details={
            "sub_type": "cross_account_movement",
            "source_account": "123456789012",
            "target_account": "111222333444",
            "assumed_role": "CrossAccountAdmin",
            "unusual_ip": True,
            "normal_ip_range": "10.0.0.0/8",
            "geo_location": "Unknown (VPN endpoint)",
        },
    ))

    # Actions in target account
    for action in ["ec2:DescribeInstances", "rds:DescribeDBInstances", "secretsmanager:ListSecrets"]:
        events.append(create_security_event(
            event_type="LATERAL_MOVEMENT",
            source_ip=attacker_ip,
            user_identity=f"assumed-role/CrossAccountAdmin/{compromised_user}",
            action=action,
            resource=f"arn:aws:iam::111222333444:*",
            outcome="success",
            severity="HIGH",
            mitre_tactic=MITRE["lateral_movement"]["tactic"],
            mitre_technique=MITRE["lateral_movement"]["technique"],
            details={
                "sub_type": "cross_account_movement",
                "phase": "discovery",
                "target_account": "111222333444",
                "api_call": action,
            },
        ))

    return events


def generate_imds_abuse():
    """EC2 instance metadata service used to steal credentials."""
    compromised_instance = "i-0abc123def456"
    source_ip = random.choice(INTERNAL_IPS)
    events = []

    # IMDS call detected
    events.append(create_security_event(
        event_type="LATERAL_MOVEMENT",
        source_ip=source_ip,
        user_identity=f"ec2-instance/{compromised_instance}",
        action="ec2:DescribeInstanceAttribute",
        resource=f"arn:aws:ec2:us-east-1:123456789012:instance/{compromised_instance}",
        outcome="success",
        severity="MEDIUM",
        mitre_tactic=MITRE["lateral_movement"]["tactic"],
        mitre_technique="T1552.005 - Cloud Instance Metadata API",
        details={
            "sub_type": "imds_abuse",
            "phase": "credential_theft",
            "metadata_endpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "imds_version": "IMDSv1",  # v1 is less secure
            "risk": "Instance credentials may be compromised via IMDSv1",
        },
    ))

    # Stolen creds used from external IP
    events.append(create_security_event(
        event_type="LATERAL_MOVEMENT",
        source_ip=random.choice(SUSPICIOUS_IPS),
        user_identity=f"assumed-role/EC2InstanceRole/{compromised_instance}",
        action="s3:ListBuckets",
        resource="arn:aws:s3:::*",
        outcome="success",
        severity="CRITICAL",
        mitre_tactic=MITRE["lateral_movement"]["tactic"],
        mitre_technique="T1552.005 - Cloud Instance Metadata API",
        details={
            "sub_type": "imds_abuse",
            "phase": "exploitation",
            "risk": "Instance role credentials used from EXTERNAL IP",
            "expected_source": source_ip,
            "actual_source": "external",
        },
    ))

    return events


def generate_ssm_session():
    """SSM session started by unexpected user."""
    attacker = random.choice(["dev-intern", "john.smith"])
    source_ip = random.choice(SUSPICIOUS_IPS)
    target_instance = random.choice([
        "i-0abc123def456",
        "i-0def789ghi012",
    ])
    events = []

    events.append(create_security_event(
        event_type="LATERAL_MOVEMENT",
        source_ip=source_ip,
        user_identity=attacker,
        action="ssm:StartSession",
        resource=f"arn:aws:ec2:us-east-1:123456789012:instance/{target_instance}",
        outcome="success",
        severity="HIGH",
        mitre_tactic=MITRE["lateral_movement"]["tactic"],
        mitre_technique=MITRE["lateral_movement"]["technique"],
        details={
            "sub_type": "ssm_session",
            "target_instance": target_instance,
            "session_id": f"sess-{random.randint(100000, 999999)}",
            "risk": "SSM session from unusual user and IP",
            "user_normally_accesses_instance": False,
        },
    ))

    return events


PATTERNS = [
    generate_cross_account_movement,
    generate_imds_abuse,
    generate_ssm_session,
]


def handler(event, context):
    pattern_name = event.get("pattern")

    if pattern_name == "cross_account":
        events = generate_cross_account_movement()
    elif pattern_name == "imds":
        events = generate_imds_abuse()
    elif pattern_name == "ssm":
        events = generate_ssm_session()
    else:
        pattern = random.choice(PATTERNS)
        events = pattern()

    return {
        "statusCode": 200,
        "attack_type": "LATERAL_MOVEMENT",
        "events_generated": len(events),
        "pattern": events[0]["details"]["sub_type"] if events else "none",
    }
