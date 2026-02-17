"""
CloudSentinel IR - Step 3: Investigate
Gathers evidence and builds attack timeline.
"""
import json
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(os.environ.get("EVENTS_TABLE", "cloudsentinel-events-dev"))


def handler(event, context):
    """Investigate the incident and gather evidence."""
    classification = event.get("classification", {})
    containment = event.get("containment", {})
    detail = event.get("detail", {})

    alert_id = classification.get("alert_id", detail.get("alert_id", "unknown"))
    source_ip = classification.get("source_ip", "N/A")
    user_identity = classification.get("user_identity", "N/A")

    # Query related events from DynamoDB
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    related_events = []

    try:
        response = events_table.query(
            KeyConditionExpression=Key("pk").eq(f"EVENT#{today}"),
            Limit=50,
        )
        all_events = response.get("Items", [])

        # Find events from same source IP or user
        for ev in all_events:
            details = ev.get("details", {})
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except:
                    details = {}

            ev_ip = ev.get("source_ip", "")
            ev_user = ev.get("user_identity", "")

            if (source_ip != "N/A" and ev_ip == source_ip) or \
               (user_identity != "N/A" and ev_user == user_identity):
                related_events.append({
                    "event_id": ev.get("sk", ""),
                    "event_type": ev.get("event_type", ""),
                    "action": ev.get("action", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "severity": ev.get("severity", ""),
                    "outcome": ev.get("outcome", ""),
                    "source": details.get("source", "simulated"),
                })
    except Exception as e:
        print(f"[IR-Investigate] Error querying events: {e}")

    # Build attack timeline
    timeline = sorted(related_events, key=lambda x: x.get("timestamp", ""))

    # Determine attack scope
    unique_types = list(set(e.get("event_type", "") for e in related_events))
    unique_actions = list(set(e.get("action", "") for e in related_events))

    # Risk assessment
    has_real_events = any(e.get("source") == "cloudtrail_real" for e in related_events)
    has_success = any(e.get("outcome") == "success" for e in related_events)

    if has_real_events and has_success:
        risk_level = "CONFIRMED_COMPROMISE"
    elif has_real_events:
        risk_level = "LIKELY_ATTACK"
    elif has_success:
        risk_level = "SIMULATED_SUCCESS"
    else:
        risk_level = "SIMULATED_ATTEMPT"

    investigation = {
        "alert_id": alert_id,
        "related_events_found": len(related_events),
        "attack_timeline": timeline[:20],  # Limit for Step Functions payload
        "attack_types_involved": unique_types,
        "unique_actions": unique_actions[:10],
        "risk_level": risk_level,
        "has_real_events": has_real_events,
        "blast_radius": {
            "affected_users": list(set(e.get("user_identity", "") for e in related_events if e.get("user_identity"))),
            "affected_ips": list(set(e.get("source_ip", "") for e in related_events if e.get("source_ip"))),
        },
        "investigated_at": datetime.now(timezone.utc).isoformat(),
        "step": "INVESTIGATE",
    }

    print(
        f"[IR-Investigate] Alert {alert_id}: {len(related_events)} related events, "
        f"risk={risk_level}, types={unique_types}"
    )

    return investigation
