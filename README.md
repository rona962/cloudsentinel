# ☁️ CloudSentinel — Serverless SIEM on AWS

A serverless Security Information and Event Management (SIEM) system built entirely on AWS. Simulates real-world attack patterns based on MITRE ATT&CK, detects threats through event correlation, and executes automated incident response.

**Cost: ~$0/month** (within AWS Free Tier)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CloudSentinel SIEM                           │
├──────────────────┬──────────────────────┬──────────────────────────┤
│   🔴 RED TEAM    │    🟡 DETECTION      │    🟢 BLUE TEAM         │
│                  │                      │                          │
│  EventBridge     │  DynamoDB Streams    │  EventBridge Rules       │
│  (scheduler)     │       │              │       │                  │
│       │          │       ▼              │       ▼                  │
│       ▼          │  Correlation         │  Auto-Responder          │
│  Orchestrator    │  Engine (Lambda)     │  (Lambda)                │
│  (Lambda)        │       │              │       │                  │
│       │          │       ├── Rules      │       ├── Playbooks      │
│       ▼          │       ├── Alerts     │       ├── Remediation    │
│  ┌──────────┐    │       └── SNS       │       └── Reports (S3)   │
│  │BruteForce│    │                      │                          │
│  │PrivEsc   │    │                      │                          │
│  │Exfil     │    │                      │                          │
│  │Lateral   │    │                      │                          │
│  └──────────┘    │                      │                          │
│       │          │                      │                          │
│       ▼          │                      │                          │
│  DynamoDB        │                      │    API Gateway           │
│  (events)        │                      │       │                  │
│                  │                      │       ▼                  │
│                  │                      │    Dashboard (S3)        │
└──────────────────┴──────────────────────┴──────────────────────────┘
```

## MITRE ATT&CK Coverage

| Tactic                | Technique                  | Simulator             |
|-----------------------|----------------------------|-----------------------|
| Credential Access     | T1110 - Brute Force        | `brute_force.py`      |
| Privilege Escalation  | T1078 - Valid Accounts     | `privilege_escalation` |
| Persistence           | T1098 - Account Manipulation| `privilege_escalation` |
| Exfiltration          | T1537 - Transfer to Cloud  | `data_exfiltration`   |
| Lateral Movement      | T1550 - Alternate Auth     | `lateral_movement`    |
| Lateral Movement      | T1552.005 - IMDS API       | `lateral_movement`    |

## Project Structure

```
cloudsentinel/
├── template.yaml           # SAM template (IaC)
├── src/
│   ├── shared/
│   │   └── utils.py        # Common utilities, MITRE mappings, fake data
│   ├── simulators/
│   │   ├── brute_force.py          # T1110 patterns
│   │   ├── privilege_escalation.py # T1078/T1098 patterns
│   │   ├── data_exfiltration.py    # T1537 patterns
│   │   └── lateral_movement.py     # T1550/T1552 patterns
│   ├── orchestrator/
│   │   └── attack_orchestrator.py  # Multi-stage attack scenarios
│   ├── detection/
│   │   └── correlation_engine.py   # Detection rules engine
│   ├── response/
│   │   └── auto_responder.py       # Automated playbooks
│   └── api/
│       └── get_alerts.py           # Dashboard API
├── SETUP_WINDOWS.md        # Windows setup guide
└── README.md
```

## Quick Start

### Prerequisites
- AWS CLI v2
- AWS SAM CLI
- Python 3.12
- An AWS account (personal, Free Tier works)

### Deploy

```bash
sam build
sam deploy --guided --profile personal
```

First deploy will ask for:
- Stack name: `cloudsentinel`
- Region: `us-east-1`
- AlertEmail: your email (optional, for SNS notifications)

### Test It

```bash
# Invoke a specific attack pattern
aws lambda invoke --function-name cloudsentinel-sim-bruteforce-dev \
  --payload '{"pattern": "single_ip"}' output.json --profile personal

# Run a full attack scenario
aws lambda invoke --function-name cloudsentinel-orchestrator-dev \
  --payload '{"scenario": "Compromised Developer Account"}' output.json --profile personal

# Check alerts via API
curl https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/alerts
curl https://<api-id>.execute-api.us-east-1.amazonaws.com/dev/stats

# Enable automated schedule (runs every 15 min)
aws events enable-rule --name cloudsentinel-attack-schedule-dev --profile personal
```

## Sprint Plan

- [x] **Sprint 1**: Attack simulators + Detection engine + Auto-response
- [ ] **Sprint 2**: Static dashboard (S3 + CloudFront) with real-time alert visualization
- [ ] **Sprint 3**: CloudTrail integration (real AWS API events, not just simulated)
- [ ] **Sprint 4**: Advanced correlation (time-window analysis, ML-based anomaly scoring)

## What This Demonstrates

- **Threat Detection & Incident Response** — core SIEM functionality
- **Event-Driven Architecture** — DynamoDB Streams, EventBridge, Lambda
- **MITRE ATT&CK Framework** — real-world attack pattern simulation
- **Infrastructure as Code** — single `sam deploy` for everything
- **Serverless Design** — zero idle cost, auto-scaling
- **Security Automation** — playbook-based remediation

## License

MIT
