"""
CloudSentinel - Privilege Escalation Simulator
MITRE ATT&CK: T1078 - Valid Accounts / T1098 - Account Manipulation

Simulates patterns:
  1. IAM policy attachment to gain admin access
  2. Role assumption chain (role hopping)
  3. Access key creation for persistence
"""
import random

from shared.utils import (
    create_security_event,
    MITRE,
    random_ip,
    random_username,
    INTERNAL_IPS,
)


def generate_iam_policy_escalation():
    """User attaches admin policy to their own account."""
    attacker = random.choice(["dev-intern", "ci-pipeline", "deploy-bot"])
    source_ip = random.choice(INTERNAL_IPS)
    events = []

    # Step 1: List policies (recon)
    events.append(create_security_event(
        event_type="PRIVILEGE_ESCALATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="iam:ListPolicies",
        resource="arn:aws:iam::123456789012:policy/*",
        outcome="success",
        severity="LOW",
        mitre_tactic=MITRE["privilege_escalation"]["tactic"],
        mitre_technique=MITRE["privilege_escalation"]["technique"],
        details={
            "sub_type": "iam_policy_escalation",
            "phase": "reconnaissance",
            "api_call": "ListPolicies",
        },
    ))

    # Step 2: Attach AdministratorAccess
    events.append(create_security_event(
        event_type="PRIVILEGE_ESCALATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="iam:AttachUserPolicy",
        resource=f"arn:aws:iam::123456789012:user/{attacker}",
        outcome="success",
        severity="CRITICAL",
        mitre_tactic=MITRE["iam_manipulation"]["tactic"],
        mitre_technique=MITRE["iam_manipulation"]["technique"],
        details={
            "sub_type": "iam_policy_escalation",
            "phase": "escalation",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "api_call": "AttachUserPolicy",
            "risk": "User granted themselves admin access",
        },
    ))

    # Step 3: Perform admin action
    events.append(create_security_event(
        event_type="PRIVILEGE_ESCALATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="ec2:DescribeInstances",
        resource="arn:aws:ec2:us-east-1:123456789012:instance/*",
        outcome="success",
        severity="HIGH",
        mitre_tactic=MITRE["privilege_escalation"]["tactic"],
        mitre_technique=MITRE["privilege_escalation"]["technique"],
        details={
            "sub_type": "iam_policy_escalation",
            "phase": "exploitation",
            "api_call": "DescribeInstances",
            "note": "User accessing resources beyond normal scope",
        },
    ))

    return events


def generate_role_chain():
    """Chained role assumptions to reach high-privilege role."""
    attacker = random_username()
    source_ip = random.choice(INTERNAL_IPS)
    roles = [
        "arn:aws:iam::123456789012:role/ReadOnlyRole",
        "arn:aws:iam::123456789012:role/DevOpsRole",
        "arn:aws:iam::123456789012:role/AdminRole",
    ]
    events = []

    for i, role in enumerate(roles):
        severity = ["LOW", "MEDIUM", "CRITICAL"][i]
        events.append(create_security_event(
            event_type="PRIVILEGE_ESCALATION",
            source_ip=source_ip,
            user_identity=attacker,
            action="sts:AssumeRole",
            resource=role,
            outcome="success",
            severity=severity,
            mitre_tactic=MITRE["privilege_escalation"]["tactic"],
            mitre_technique=MITRE["privilege_escalation"]["technique"],
            details={
                "sub_type": "role_chain",
                "hop_number": i + 1,
                "total_hops": len(roles),
                "assumed_role": role.split("/")[-1],
                "session_duration": 3600,
            },
        ))

    return events


def generate_access_key_creation():
    """Creation of new access key for persistence."""
    attacker = random.choice(["dev-intern", "john.smith"])
    source_ip = random.choice(INTERNAL_IPS)
    events = []

    # Create access key for another user (suspicious)
    target_user = "svc-backup"
    events.append(create_security_event(
        event_type="PRIVILEGE_ESCALATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="iam:CreateAccessKey",
        resource=f"arn:aws:iam::123456789012:user/{target_user}",
        outcome="success",
        severity="HIGH",
        mitre_tactic=MITRE["iam_manipulation"]["tactic"],
        mitre_technique=MITRE["iam_manipulation"]["technique"],
        details={
            "sub_type": "access_key_creation",
            "target_user": target_user,
            "creator": attacker,
            "risk": "Access key created for different user (possible persistence)",
            "new_key_id": "AKIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=16)),
        },
    ))

    return events


PATTERNS = [
    generate_iam_policy_escalation,
    generate_role_chain,
    generate_access_key_creation,
]


def handler(event, context):
    pattern_name = event.get("pattern")

    if pattern_name == "iam_policy":
        events = generate_iam_policy_escalation()
    elif pattern_name == "role_chain":
        events = generate_role_chain()
    elif pattern_name == "access_key":
        events = generate_access_key_creation()
    else:
        pattern = random.choice(PATTERNS)
        events = pattern()

    return {
        "statusCode": 200,
        "attack_type": "PRIVILEGE_ESCALATION",
        "events_generated": len(events),
        "pattern": events[0]["details"]["sub_type"] if events else "none",
    }
