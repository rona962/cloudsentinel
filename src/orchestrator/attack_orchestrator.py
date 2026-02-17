"""
CloudSentinel - Attack Orchestrator
Selects and executes random attack patterns to simulate realistic threat activity.
Invoked by EventBridge on a schedule.
"""
import json
import os
import random

import boto3

lambda_client = boto3.client("lambda")

# Attack functions loaded from environment
ATTACK_FUNCTIONS = {
    "BRUTE_FORCE": os.environ.get("BRUTE_FORCE_FN"),
    "PRIVILEGE_ESCALATION": os.environ.get("PRIV_ESC_FN"),
    "DATA_EXFILTRATION": os.environ.get("EXFIL_FN"),
    "LATERAL_MOVEMENT": os.environ.get("LATERAL_FN"),
}

# Attack scenarios: sequences that simulate realistic multi-stage attacks
SCENARIOS = [
    {
        "name": "Compromised Developer Account",
        "description": "Attacker brute-forces developer creds, escalates, exfils data",
        "sequence": [
            ("BRUTE_FORCE", {"pattern": "single_ip"}),
            ("PRIVILEGE_ESCALATION", {"pattern": "iam_policy"}),
            ("DATA_EXFILTRATION", {"pattern": "mass_download"}),
        ],
    },
    {
        "name": "Insider Threat",
        "description": "Employee creates backdoor access key and copies data externally",
        "sequence": [
            ("PRIVILEGE_ESCALATION", {"pattern": "access_key"}),
            ("DATA_EXFILTRATION", {"pattern": "cross_account"}),
        ],
    },
    {
        "name": "Cloud Infrastructure Attack",
        "description": "Attacker compromises EC2 via IMDS, moves laterally, changes bucket policy",
        "sequence": [
            ("LATERAL_MOVEMENT", {"pattern": "imds"}),
            ("LATERAL_MOVEMENT", {"pattern": "cross_account"}),
            ("DATA_EXFILTRATION", {"pattern": "bucket_policy"}),
        ],
    },
    {
        "name": "Password Spray Campaign",
        "description": "Broad password spray followed by targeted credential stuffing",
        "sequence": [
            ("BRUTE_FORCE", {"pattern": "spray"}),
            ("BRUTE_FORCE", {"pattern": "stuffing"}),
        ],
    },
    {
        "name": "Single Random Attack",
        "description": "One random attack type - simulates opportunistic threat",
        "sequence": None,  # Will be filled dynamically
    },
]


def invoke_attack(attack_type: str, payload: dict) -> dict:
    """Invoke an attack simulator Lambda function."""
    fn_name = ATTACK_FUNCTIONS.get(attack_type)
    if not fn_name:
        return {"error": f"Unknown attack type: {attack_type}"}

    response = lambda_client.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload),
    )

    result = json.loads(response["Payload"].read())
    return result


def handler(event, context):
    """
    Lambda handler - execute an attack scenario.

    Can be invoked with a specific scenario:
      {"scenario": "Compromised Developer Account"}

    Or without payload for random selection.
    """
    requested_scenario = event.get("scenario") if isinstance(event, dict) else None

    # Select scenario
    if requested_scenario:
        scenario = next(
            (s for s in SCENARIOS if s["name"] == requested_scenario),
            None,
        )
        if not scenario:
            return {
                "statusCode": 400,
                "error": f"Unknown scenario: {requested_scenario}",
                "available": [s["name"] for s in SCENARIOS],
            }
    else:
        scenario = random.choice(SCENARIOS)

    # Handle "Single Random Attack" - pick one random type
    if scenario["sequence"] is None:
        attack_type = random.choice(list(ATTACK_FUNCTIONS.keys()))
        scenario["sequence"] = [(attack_type, {})]

    # Execute attack sequence
    results = []
    total_events = 0

    for attack_type, payload in scenario["sequence"]:
        result = invoke_attack(attack_type, payload)
        results.append(result)
        total_events += result.get("events_generated", 0)

    return {
        "statusCode": 200,
        "scenario": scenario["name"],
        "description": scenario["description"],
        "attacks_executed": len(results),
        "total_events_generated": total_events,
        "details": results,
    }
