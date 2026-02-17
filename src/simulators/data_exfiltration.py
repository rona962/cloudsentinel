"""
CloudSentinel - Data Exfiltration Simulator
MITRE ATT&CK: T1537 - Transfer Data to Cloud Account

Simulates patterns:
  1. Mass S3 object downloads
  2. S3 bucket policy change to allow external access
  3. Cross-account data copy
"""
import random

from shared.utils import (
    create_security_event,
    MITRE,
    random_ip,
    SUSPICIOUS_IPS,
    INTERNAL_IPS,
)


def generate_mass_download():
    """Unusual volume of S3 GetObject calls in short time."""
    attacker = random.choice(["dev-intern", "ci-pipeline"])
    source_ip = random.choice(INTERNAL_IPS)
    bucket = "company-secrets-bucket"
    file_count = random.randint(50, 200)
    events = []

    # Recon: list bucket
    events.append(create_security_event(
        event_type="DATA_EXFILTRATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="s3:ListBucket",
        resource=f"arn:aws:s3:::{bucket}",
        outcome="success",
        severity="LOW",
        mitre_tactic=MITRE["data_exfiltration"]["tactic"],
        mitre_technique=MITRE["data_exfiltration"]["technique"],
        details={
            "sub_type": "mass_download",
            "phase": "reconnaissance",
            "bucket": bucket,
        },
    ))

    # Mass download events (summarised, not 200 individual events)
    events.append(create_security_event(
        event_type="DATA_EXFILTRATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="s3:GetObject",
        resource=f"arn:aws:s3:::{bucket}/*",
        outcome="success",
        severity="HIGH",
        mitre_tactic=MITRE["data_exfiltration"]["tactic"],
        mitre_technique=MITRE["data_exfiltration"]["technique"],
        details={
            "sub_type": "mass_download",
            "phase": "exfiltration",
            "bucket": bucket,
            "objects_accessed": file_count,
            "estimated_data_mb": round(file_count * random.uniform(0.5, 5.0), 1),
            "time_window_seconds": random.randint(30, 300),
            "unusual_pattern": True,
            "baseline_daily_downloads": random.randint(5, 15),
        },
    ))

    return events


def generate_bucket_policy_change():
    """S3 bucket policy changed to allow public or external account access."""
    attacker = random.choice(["deploy-bot", "john.smith"])
    source_ip = random.choice(INTERNAL_IPS)
    bucket = "financial-reports-2025"
    events = []

    # Change bucket policy
    events.append(create_security_event(
        event_type="DATA_EXFILTRATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="s3:PutBucketPolicy",
        resource=f"arn:aws:s3:::{bucket}",
        outcome="success",
        severity="CRITICAL",
        mitre_tactic=MITRE["data_exfiltration"]["tactic"],
        mitre_technique=MITRE["data_exfiltration"]["technique"],
        details={
            "sub_type": "bucket_policy_change",
            "bucket": bucket,
            "change_type": random.choice(["public_access", "cross_account_access"]),
            "new_principal": random.choice(["*", "arn:aws:iam::999888777666:root"]),
            "risk": "Bucket policy now allows external access",
        },
    ))

    # External access from suspicious IP
    events.append(create_security_event(
        event_type="DATA_EXFILTRATION",
        source_ip=random.choice(SUSPICIOUS_IPS),
        user_identity="anonymous" if random.random() > 0.5 else "arn:aws:iam::999888777666:user/exfil-bot",
        action="s3:GetObject",
        resource=f"arn:aws:s3:::{bucket}/financial-summary-2025.xlsx",
        outcome="success",
        severity="CRITICAL",
        mitre_tactic=MITRE["data_exfiltration"]["tactic"],
        mitre_technique=MITRE["data_exfiltration"]["technique"],
        details={
            "sub_type": "bucket_policy_change",
            "phase": "exfiltration",
            "bucket": bucket,
            "external_access": True,
            "time_after_policy_change_seconds": random.randint(60, 600),
        },
    ))

    return events


def generate_cross_account_copy():
    """Data copied to external AWS account."""
    attacker = "svc-backup"
    source_ip = random.choice(INTERNAL_IPS)
    events = []

    events.append(create_security_event(
        event_type="DATA_EXFILTRATION",
        source_ip=source_ip,
        user_identity=attacker,
        action="s3:PutObject",
        resource="arn:aws:s3:::external-staging-bucket-999888/exfil-data.tar.gz",
        outcome="success",
        severity="CRITICAL",
        mitre_tactic=MITRE["data_exfiltration"]["tactic"],
        mitre_technique=MITRE["data_exfiltration"]["technique"],
        details={
            "sub_type": "cross_account_copy",
            "source_bucket": "company-secrets-bucket",
            "destination_bucket": "external-staging-bucket-999888",
            "destination_account": "999888777666",
            "file_size_mb": round(random.uniform(50, 500), 1),
            "risk": "Data copied to unknown external account",
        },
    ))

    return events


PATTERNS = [
    generate_mass_download,
    generate_bucket_policy_change,
    generate_cross_account_copy,
]


def handler(event, context):
    pattern_name = event.get("pattern")

    if pattern_name == "mass_download":
        events = generate_mass_download()
    elif pattern_name == "bucket_policy":
        events = generate_bucket_policy_change()
    elif pattern_name == "cross_account":
        events = generate_cross_account_copy()
    else:
        pattern = random.choice(PATTERNS)
        events = pattern()

    return {
        "statusCode": 200,
        "attack_type": "DATA_EXFILTRATION",
        "events_generated": len(events),
        "pattern": events[0]["details"]["sub_type"] if events else "none",
    }
