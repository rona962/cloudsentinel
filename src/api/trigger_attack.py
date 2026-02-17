"""
CloudSentinel - Attack Trigger API
Allows launching attack scenarios from the dashboard.
"""
import json
import os

import boto3

lambda_client = boto3.client("lambda")
ORCHESTRATOR_FN = os.environ.get("ORCHESTRATOR_FN", "")

SCENARIOS = [
    {
        "id": "compromised_dev",
        "name": "Compromised Developer Account",
        "description": "Brute-force → privilege escalation → data exfiltration",
        "severity": "CRITICAL",
        "attacks": 3,
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat",
        "description": "Backdoor access key creation → cross-account data copy",
        "severity": "HIGH",
        "attacks": 2,
    },
    {
        "id": "cloud_infra",
        "name": "Cloud Infrastructure Attack",
        "description": "IMDS abuse → lateral movement → bucket policy change",
        "severity": "CRITICAL",
        "attacks": 3,
    },
    {
        "id": "password_spray",
        "name": "Password Spray Campaign",
        "description": "Broad password spray → targeted credential stuffing",
        "severity": "MEDIUM",
        "attacks": 2,
    },
    {
        "id": "random",
        "name": "Single Random Attack",
        "description": "One random attack type — simulates opportunistic threat",
        "severity": "VARIES",
        "attacks": 1,
    },
]

SCENARIO_MAP = {
    "compromised_dev": "Compromised Developer Account",
    "insider_threat": "Insider Threat",
    "cloud_infra": "Cloud Infrastructure Attack",
    "password_spray": "Password Spray Campaign",
    "random": "Single Random Attack",
}


def cors_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body, default=str),
    }


def handler(event, context):
    method = event.get("httpMethod", "GET")
    path = event.get("path", "")

    if method == "OPTIONS":
        return cors_response(200, {"message": "OK"})

    # GET /scenarios — list available scenarios
    if path == "/scenarios" and method == "GET":
        return cors_response(200, {"scenarios": SCENARIOS})

    # POST /attack — trigger a scenario
    if path == "/attack" and method == "POST":
        try:
            body = json.loads(event.get("body", "{}"))
        except json.JSONDecodeError:
            return cors_response(400, {"error": "Invalid JSON"})

        scenario_id = body.get("scenario_id", "random")
        scenario_name = SCENARIO_MAP.get(scenario_id)

        if not scenario_name:
            return cors_response(400, {
                "error": f"Unknown scenario: {scenario_id}",
                "available": list(SCENARIO_MAP.keys()),
            })

        # Invoke orchestrator
        response = lambda_client.invoke(
            FunctionName=ORCHESTRATOR_FN,
            InvocationType="RequestResponse",
            Payload=json.dumps({"scenario": scenario_name}),
        )

        result = json.loads(response["Payload"].read())

        return cors_response(200, {
            "status": "executed",
            "scenario": scenario_name,
            "result": result,
        })

    return cors_response(404, {"error": "Not found"})
