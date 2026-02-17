"""
CloudSentinel - Dashboard API
Returns alerts and stats for the frontend dashboard.
"""
import json
import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table(os.environ["ALERTS_TABLE"])
events_table = dynamodb.Table(os.environ["EVENTS_TABLE"])


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj) if obj % 1 else int(obj)
        return super().default(obj)


def cors_response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,OPTIONS",
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }


def get_alerts(query_params: dict) -> dict:
    """Get recent alerts, optionally filtered by severity."""
    severity = query_params.get("severity")
    limit = int(query_params.get("limit", "20"))

    if severity:
        response = alerts_table.query(
            IndexName="BySeverity",
            KeyConditionExpression=Key("severity").eq(severity),
            ScanIndexForward=False,
            Limit=limit,
        )
    else:
        # Scan for all alerts (fine for demo scale)
        response = alerts_table.scan(Limit=limit)
        response["Items"].sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return {
        "alerts": response["Items"][:limit],
        "count": len(response["Items"]),
    }


def get_stats() -> dict:
    """Get summary statistics for the dashboard."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Get today's events count
    try:
        events_response = events_table.query(
            KeyConditionExpression=Key("pk").eq(f"EVENT#{today}"),
            Select="COUNT",
        )
        events_today = events_response["Count"]
    except Exception:
        events_today = 0

    # Get alerts by severity
    severity_counts = {}
    for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        try:
            resp = alerts_table.query(
                IndexName="BySeverity",
                KeyConditionExpression=Key("severity").eq(sev),
                Select="COUNT",
            )
            severity_counts[sev] = resp["Count"]
        except Exception:
            severity_counts[sev] = 0

    # Get recent alerts for activity feed
    try:
        scan_resp = alerts_table.scan(Limit=5)
        recent = sorted(scan_resp["Items"], key=lambda x: x.get("created_at", ""), reverse=True)[:5]
    except Exception:
        recent = []

    return {
        "events_today": events_today,
        "alerts_by_severity": severity_counts,
        "total_open_alerts": sum(severity_counts.values()),
        "recent_alerts": recent,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


def handler(event, context):
    """API Gateway handler for /alerts and /stats endpoints."""
    path = event.get("path", "")
    method = event.get("httpMethod", "GET")
    query_params = event.get("queryStringParameters") or {}

    if method == "OPTIONS":
        return cors_response(200, {"message": "OK"})

    if path == "/alerts":
        data = get_alerts(query_params)
        return cors_response(200, data)

    elif path == "/stats":
        data = get_stats()
        return cors_response(200, data)

    return cors_response(404, {"error": "Not found"})
