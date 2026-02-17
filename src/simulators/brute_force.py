"""
CloudSentinel - Brute Force Attack Simulator
MITRE ATT&CK: T1110 - Brute Force

Simulates patterns:
  1. Multiple failed login attempts from a single IP
  2. Password spraying (one password, many users)
  3. Credential stuffing (IP rotation with same user)
"""
import random
import time

from shared.utils import (
    create_security_event,
    MITRE,
    random_ip,
    random_username,
    SUSPICIOUS_IPS,
    USERNAMES,
)


def generate_single_ip_brute_force():
    """Multiple failed logins from one IP targeting one account."""
    attacker_ip = random_ip(suspicious=True)
    target_user = random.choice(["admin", "root"])
    attempts = random.randint(5, 20)
    events = []

    for i in range(attempts):
        outcome = "failure" if i < attempts - 1 else random.choice(["failure", "success"])
        severity = "MEDIUM" if outcome == "failure" else "CRITICAL"

        event = create_security_event(
            event_type="BRUTE_FORCE",
            source_ip=attacker_ip,
            user_identity=target_user,
            action="ConsoleLogin",
            resource="arn:aws:iam::123456789012:user/" + target_user,
            outcome=outcome,
            severity=severity,
            mitre_tactic=MITRE["brute_force"]["tactic"],
            mitre_technique=MITRE["brute_force"]["technique"],
            details={
                "sub_type": "single_ip_brute_force",
                "attempt_number": i + 1,
                "total_attempts": attempts,
                "user_agent": "Mozilla/5.0 (compatible; BruteBot/1.0)",
                "mfa_used": False,
                "geo_location": random.choice([
                    "Moscow, RU", "Beijing, CN", "Lagos, NG", "São Paulo, BR"
                ]),
            },
        )
        events.append(event)

    return events


def generate_password_spray():
    """One password tried against many accounts from one IP."""
    attacker_ip = random_ip(suspicious=True)
    targets = random.sample(USERNAMES, k=min(random.randint(4, 8), len(USERNAMES)))
    events = []

    for user in targets:
        event = create_security_event(
            event_type="BRUTE_FORCE",
            source_ip=attacker_ip,
            user_identity=user,
            action="ConsoleLogin",
            resource=f"arn:aws:iam::123456789012:user/{user}",
            outcome="failure",
            severity="MEDIUM",
            mitre_tactic=MITRE["brute_force"]["tactic"],
            mitre_technique=MITRE["brute_force"]["technique"],
            details={
                "sub_type": "password_spray",
                "target_count": len(targets),
                "user_agent": "python-requests/2.28.1",
                "geo_location": "Unknown (TOR Exit Node)",
            },
        )
        events.append(event)

    return events


def generate_credential_stuffing():
    """Rotating IPs targeting a single high-value account."""
    target_user = "admin"
    ips = random.sample(SUSPICIOUS_IPS, k=min(3, len(SUSPICIOUS_IPS)))
    events = []

    for ip in ips:
        for _ in range(random.randint(2, 4)):
            event = create_security_event(
                event_type="BRUTE_FORCE",
                source_ip=ip,
                user_identity=target_user,
                action="ConsoleLogin",
                resource=f"arn:aws:iam::123456789012:user/{target_user}",
                outcome="failure",
                severity="HIGH",
                mitre_tactic=MITRE["brute_force"]["tactic"],
                mitre_technique=MITRE["brute_force"]["technique"],
                details={
                    "sub_type": "credential_stuffing",
                    "ip_rotation_detected": True,
                    "user_agent": "curl/7.88.1",
                },
            )
            events.append(event)

    return events


# ── Available attack patterns ────────────────────────────────────

PATTERNS = [
    generate_single_ip_brute_force,
    generate_password_spray,
    generate_credential_stuffing,
]


def handler(event, context):
    """Lambda handler - run a random brute force pattern."""
    pattern_name = event.get("pattern")

    if pattern_name == "single_ip":
        events = generate_single_ip_brute_force()
    elif pattern_name == "spray":
        events = generate_password_spray()
    elif pattern_name == "stuffing":
        events = generate_credential_stuffing()
    else:
        # Random pattern
        pattern = random.choice(PATTERNS)
        events = pattern()

    return {
        "statusCode": 200,
        "attack_type": "BRUTE_FORCE",
        "events_generated": len(events),
        "pattern": events[0]["details"]["sub_type"] if events else "none",
    }
