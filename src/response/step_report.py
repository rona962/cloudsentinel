"""
CloudSentinel IR - Step 5: Report
Generates incident report, saves to S3, and sends notifications.
"""
import json
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table(os.environ.get("ALERTS_TABLE", "cloudsentinel-alerts-dev"))

INCIDENTS_BUCKET = os.environ.get("INCIDENTS_BUCKET", "")
ALERT_TOPIC = os.environ.get("ALERT_TOPIC", "")


def handler(event, context):
    """Generate final incident report and notify."""
    mode = event.get("mode", "full")
    classification = event.get("classification", {})
    containment = event.get("containment", {})
    investigation = event.get("investigation", {})
    remediation = event.get("remediation", {})
    detail = event.get("detail", event.get("alert", {}))
    error = event.get("error", None)

    alert_id = classification.get("alert_id", detail.get("alert_id", "unknown"))
    severity = classification.get("severity", detail.get("severity", "MEDIUM"))

    # Build comprehensive report
    report = {
        "incident_id": alert_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workflow_mode": mode,
        "summary": {
            "severity": severity,
            "priority_score": classification.get("priority_score", 0),
            "response_mode": classification.get("response_mode", "standard"),
            "risk_level": investigation.get("risk_level", remediation.get("risk_level", "UNKNOWN")),
            "risk_factors": classification.get("risk_factors", []),
        },
        "classification": classification,
        "containment": {
            "mode": containment.get("mode", "N/A"),
            "actions_executed": containment.get("actions_executed", 0),
            "actions": containment.get("actions", []),
            "status": containment.get("status", "N/A"),
        },
        "investigation": {
            "related_events": investigation.get("related_events_found", 0),
            "attack_types": investigation.get("attack_types_involved", []),
            "risk_level": investigation.get("risk_level", "UNKNOWN"),
            "has_real_events": investigation.get("has_real_events", False),
            "blast_radius": investigation.get("blast_radius", {}),
            "timeline_entries": len(investigation.get("attack_timeline", [])),
        },
        "remediation": {
            "actions_executed": remediation.get("actions_executed", 0),
            "actions": remediation.get("actions", []),
            "status": remediation.get("status", "N/A"),
        },
        "workflow_steps": [
            {"step": "CLASSIFY", "timestamp": classification.get("classified_at", ""), "status": "COMPLETED"},
            {"step": "CONTAIN", "timestamp": containment.get("contained_at", ""), "status": "COMPLETED" if containment else "SKIPPED"},
            {"step": "INVESTIGATE", "timestamp": investigation.get("investigated_at", ""), "status": "COMPLETED" if investigation else "SKIPPED"},
            {"step": "REMEDIATE", "timestamp": remediation.get("remediated_at", ""), "status": "COMPLETED" if remediation else "SKIPPED"},
            {"step": "REPORT", "timestamp": datetime.now(timezone.utc).isoformat(), "status": "COMPLETED"},
        ],
    }

    if error:
        report["error"] = str(error)
        report["workflow_steps"].append({"step": "ERROR_HANDLER", "status": "TRIGGERED"})

    # Save report to S3
    report_key = f"incidents/{alert_id}.json"
    report_location = ""

    if INCIDENTS_BUCKET:
        try:
            s3_client.put_object(
                Bucket=INCIDENTS_BUCKET,
                Key=report_key,
                Body=json.dumps(report, indent=2, default=str),
                ContentType="application/json",
            )
            report_location = f"s3://{INCIDENTS_BUCKET}/{report_key}"
            print(f"[IR-Report] Saved to {report_location}")
        except Exception as e:
            print(f"[IR-Report] S3 error: {e}")

    # Update alert in DynamoDB with final status
    try:
        alert_data = detail if detail else classification
        created_at = alert_data.get("created_at", datetime.now(timezone.utc).isoformat())

        update_expr = "SET #s = :status, report_location = :report, response_actions = :actions"
        expr_values = {
            ":status": "CONTAINED",
            ":report": report_location,
            ":actions": containment.get("actions_executed", 0) + remediation.get("actions_executed", 0),
        }

        alerts_table.update_item(
            Key={"alert_id": alert_id, "created_at": created_at},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=expr_values,
        )
    except Exception as e:
        print(f"[IR-Report] DynamoDB update error: {e}")

    # Send SNS notification
    if ALERT_TOPIC and severity in ("CRITICAL", "HIGH"):
        risk_level = report["summary"]["risk_level"]
        containment_count = containment.get("actions_executed", 0)
        remediation_count = remediation.get("actions_executed", 0)

        subject = f"[CloudSentinel] {severity} - IR Workflow Complete: {alert_id[:8]}"

        message = (
            f"══════════════════════════════════════\n"
            f"  CLOUDSENTINEL INCIDENT RESPONSE\n"
            f"══════════════════════════════════════\n\n"
            f"Alert ID:      {alert_id}\n"
            f"Severity:      {severity}\n"
            f"Risk Level:    {risk_level}\n"
            f"Priority Score: {classification.get('priority_score', 'N/A')}\n\n"
            f"── Risk Factors ──\n"
        )

        for factor in classification.get("risk_factors", ["None identified"]):
            message += f"  • {factor}\n"

        message += (
            f"\n── Workflow Results ──\n"
            f"  1. CLASSIFY:    ✓ Score {classification.get('priority_score', '?')}, Mode: {classification.get('response_mode', '?')}\n"
            f"  2. CONTAIN:     ✓ {containment_count} actions executed\n"
            f"  3. INVESTIGATE: ✓ {investigation.get('related_events_found', '?')} related events found\n"
            f"  4. REMEDIATE:   ✓ {remediation_count} remediation actions\n"
            f"  5. REPORT:      ✓ Saved to S3\n\n"
            f"── Blast Radius ──\n"
            f"  Affected Users: {investigation.get('blast_radius', {}).get('affected_users', ['N/A'])}\n"
            f"  Affected IPs:   {investigation.get('blast_radius', {}).get('affected_ips', ['N/A'])}\n\n"
            f"Report: {report_location}\n\n"
            f"══════════════════════════════════════\n"
        )

        try:
            sns_client.publish(
                TopicArn=ALERT_TOPIC,
                Subject=subject[:100],
                Message=message,
            )
            print(f"[IR-Report] SNS notification sent for {alert_id}")
        except Exception as e:
            print(f"[IR-Report] SNS error: {e}")

    result = {
        "alert_id": alert_id,
        "report_location": report_location,
        "total_actions": containment.get("actions_executed", 0) + remediation.get("actions_executed", 0),
        "status": "RESOLVED",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "step": "REPORT",
    }

    print(f"[IR-Report] Alert {alert_id}: workflow complete, {result['total_actions']} total actions")

    return result
