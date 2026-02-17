# 🛡️ CloudSentinel — Serverless SIEM on AWS

A complete serverless Security Information and Event Management (SIEM) system built on AWS. Simulates real-world attack patterns (MITRE ATT&CK), detects threats through event correlation, executes automated incident response via Step Functions, monitors real AWS activity via CloudTrail, and provides an authenticated dashboard with Cognito.

**Cost: ~$0/month** (AWS Free Tier)

---

## Architecture

```
                         ┌──────────────────────────────────┐
                         │        CloudFront (HTTPS)        │
                         │     S3 Static Dashboard + Auth   │
                         │         Cognito Login            │
                         └──────────────┬───────────────────┘
                                        │ JWT Token
                         ┌──────────────▼───────────────────┐
                         │     API Gateway (Authorized)      │
                         │   /stats  /alerts  /attack        │
                         └──────────────┬───────────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬────────────────┐
        ▼               ▼               ▼               ▼                ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
  │🔴 Attack │   │🔴 Attack │   │🟡 Detect │   │🟢 Step   │   │🔵 CloudTrail │
  │Simulators│   │Orchestr. │   │Engine    │   │Functions │   │  Processor   │
  │(4 types) │   │          │   │(5 rules) │   │(5 steps) │   │              │
  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘   └──────┬───────┘
       │              │              │              │                 │
       ▼              ▼              │              ▼                 │
  ┌─────────────────────┐           │    ┌───────────────────┐       │
  │  DynamoDB            │◄──────────┘    │ Classify→Contain  │       │
  │  Events + Alerts     │───Streams──►   │ →Investigate      │       │
  └─────────────────────┘                │ →Remediate→Report │       │
                                         └────────┬──────────┘       │
                                                  │                  │
                                    ┌─────────────▼──────────┐       │
                                    │  SNS Email Alerts      │       │
                                    │  S3 Incident Reports   │       │
                                    └────────────────────────┘       │
                                                                     │
                         ┌───────────────────────────────────────────┘
                         │  EventBridge ← CloudTrail (real AWS API calls)
                         │  Detects: IAM changes, failed logins,
                         │  bucket policy mods, AccessDenied, AssumeRole
                         └───────────────────────────────────────────
```

## What's Included

| Sprint | Feature | Resources |
|--------|---------|-----------|
| 1 | Attack simulators + Detection + Auto-response | 4 Lambdas, DynamoDB Streams, EventBridge, SNS |
| 2 | Interactive dashboard + Attack launcher | S3, CloudFront, API Gateway |
| 3 | Real AWS monitoring via CloudTrail | CloudTrail, EventBridge, Lambda processor |
| 4 | Step Functions IR workflow + Cognito auth | State Machine (5 steps), Cognito User Pool |

## MITRE ATT&CK Coverage

| Tactic | Technique | Simulator |
|--------|-----------|-----------|
| Credential Access | T1110 - Brute Force | `brute_force.py` |
| Privilege Escalation | T1078 - Valid Accounts | `privilege_escalation.py` |
| Persistence | T1098 - Account Manipulation | `privilege_escalation.py` |
| Exfiltration | T1537 - Transfer to Cloud | `data_exfiltration.py` |
| Lateral Movement | T1550 - Alternate Auth | `lateral_movement.py` |
| Lateral Movement | T1552.005 - IMDS API | `lateral_movement.py` |

## Project Structure

```
cloudsentinel/
├── template.yaml                    # SAM/CloudFormation (all infrastructure)
├── statemachine/
│   └── ir_workflow.asl.json         # Step Functions definition
├── dashboard/
│   └── index.html                   # Full dashboard with Cognito login
├── src/
│   ├── shared/
│   │   └── utils.py                 # Common utilities, MITRE mappings
│   ├── simulators/
│   │   ├── brute_force.py           # T1110 patterns
│   │   ├── privilege_escalation.py  # T1078/T1098 patterns
│   │   ├── data_exfiltration.py     # T1537 patterns
│   │   └── lateral_movement.py      # T1550/T1552 patterns
│   ├── orchestrator/
│   │   └── attack_orchestrator.py   # Multi-stage attack scenarios
│   ├── detection/
│   │   └── correlation_engine.py    # 5 detection rules
│   ├── response/
│   │   ├── auto_responder.py        # Legacy single-Lambda responder
│   │   ├── step_classify.py         # IR Step 1: Classify & enrich
│   │   ├── step_contain.py          # IR Step 2: Containment playbooks
│   │   ├── step_investigate.py      # IR Step 3: Evidence & timeline
│   │   ├── step_remediate.py        # IR Step 4: Remediation actions
│   │   └── step_report.py           # IR Step 5: Report & notify
│   ├── cloudtrail/
│   │   └── trail_processor.py       # Real AWS event analyzer
│   └── api/
│       ├── get_alerts.py            # Dashboard data API
│       └── trigger_attack.py        # Attack launcher API
└── README.md
```

---

## Prerequisites

- **AWS CLI v2** — configured with a named profile
- **AWS SAM CLI** — for build and deploy
- **Python 3.12**
- **Git**
- An AWS account (Free Tier works)

---

## Deploy (Fresh Account)

### 1. Clone

```bash
git clone https://github.com/rona962/cloudsentinel.git
cd cloudsentinel
```

### 2. Configure AWS CLI profile

```bash
# If you haven't configured a profile yet:
aws configure --profile myprofile
# Enter: Access Key, Secret Key, Region (us-east-1), Output (json)
```

### 3. Create the S3 deploy bucket

SAM needs an S3 bucket to upload Lambda code. Replace `ACCOUNT_ID` with your AWS account ID:

```bash
aws s3 mb s3://cloudsentinel-deploy-ACCOUNT_ID --profile myprofile
```

> To find your account ID: `aws sts get-caller-identity --profile myprofile`

### 4. Build and deploy

```bash
# Windows: add Python to PATH if needed
$env:Path = "C:\Users\YOUR_USER\AppData\Local\Programs\Python\Python312;" + $env:Path

# Build
sam build

# Deploy (replace ACCOUNT_ID and EMAIL)
sam deploy \
  --s3-bucket cloudsentinel-deploy-ACCOUNT_ID \
  --stack-name cloudsentinel \
  --profile myprofile \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Environment=dev AlertEmail=your@email.com
```

### 5. Note the outputs

After deploy, CloudFormation prints outputs. Save these:

```
ApiUrl              → https://XXXXXXX.execute-api.us-east-1.amazonaws.com/dev
CognitoUserPoolId   → us-east-1_XXXXXXXXX
CognitoClientId     → XXXXXXXXXXXXXXXXXXXXXXXXXX
```

### 6. Configure the dashboard

Edit `dashboard/index.html` and update the CONFIG section (around line 225):

```javascript
const CONFIG = {
  API_BASE: 'https://XXXXXXX.execute-api.us-east-1.amazonaws.com/dev',  // ← ApiUrl output
  COGNITO_USER_POOL_ID: 'us-east-1_XXXXXXXXX',                          // ← CognitoUserPoolId output
  COGNITO_CLIENT_ID: 'XXXXXXXXXXXXXXXXXXXXXXXXXX',                       // ← CognitoClientId output
  REGION: 'us-east-1',
};
```

### 7. Deploy the dashboard

```bash
# Create dashboard bucket (replace ACCOUNT_ID)
aws s3 mb s3://cloudsentinel-dashboard-ACCOUNT_ID --profile myprofile

# Enable website hosting
aws s3 website s3://cloudsentinel-dashboard-ACCOUNT_ID --index-document index.html

# Upload
aws s3 cp dashboard/index.html s3://cloudsentinel-dashboard-ACCOUNT_ID/index.html --content-type "text/html" --profile myprofile

# Set public access (for website hosting)
aws s3api put-public-access-block --bucket cloudsentinel-dashboard-ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false --profile myprofile

aws s3api put-bucket-policy --bucket cloudsentinel-dashboard-ACCOUNT_ID --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::cloudsentinel-dashboard-ACCOUNT_ID/*\"}]}" --profile myprofile
```

### 8. (Optional) Add CloudFront for HTTPS

```bash
aws cloudfront create-distribution \
  --origin-domain-name cloudsentinel-dashboard-ACCOUNT_ID.s3-website-us-east-1.amazonaws.com \
  --default-root-object index.html \
  --profile myprofile
```

Save the Distribution ID and CloudFront domain from the output.

### 9. Create your first user

```bash
aws cognito-idp admin-create-user \
  --user-pool-id us-east-1_XXXXXXXXX \
  --username your@email.com \
  --user-attributes Name=email,Value=your@email.com \
  --temporary-password "TempPass1!" \
  --profile myprofile
```

Open the dashboard URL and login. You'll be prompted to change the temporary password.

---

## Test It

```bash
# Run a full attack scenario (generates ~19 events, triggers detection + Step Functions)
aws lambda invoke --function-name cloudsentinel-orchestrator-dev \
  --payload '{"scenario": "Compromised Developer Account"}' \
  output.json --profile myprofile

# Check results
cat output.json

# View stats via API
curl https://XXXXXXX.execute-api.us-east-1.amazonaws.com/dev/stats

# Test real CloudTrail detection (creates and deletes a test user)
aws iam create-user --user-name sentinel-test --profile myprofile
aws iam attach-user-policy --user-name sentinel-test --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile myprofile
aws iam detach-user-policy --user-name sentinel-test --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile myprofile
aws iam delete-user --user-name sentinel-test --profile myprofile

# Wait 2-5 minutes, then check CloudTrail processor logs
aws logs tail /aws/lambda/cloudsentinel-trail-processor-dev --since 10m --profile myprofile

# View Step Functions executions in AWS Console:
# → Step Functions → cloudsentinel-incident-response-dev → Executions
```

---

## Tear Down (Stop All Costs)

```bash
# 1. Stop CloudTrail logging
aws cloudtrail stop-logging --name cloudsentinel-trail-dev --profile myprofile

# 2. Empty all buckets
aws s3 rm s3://cloudsentinel-trail-ACCOUNT_ID-dev --recursive --profile myprofile
aws s3 rm s3://cloudsentinel-incidents-ACCOUNT_ID-dev --recursive --profile myprofile
aws s3 rm s3://cloudsentinel-dashboard-ACCOUNT_ID --recursive --profile myprofile

# 3. Delete the CloudFormation stack (removes ~45 resources)
aws cloudformation delete-stack --stack-name cloudsentinel --profile myprofile
aws cloudformation wait stack-delete-complete --stack-name cloudsentinel --profile myprofile

# 4. Delete dashboard bucket
aws s3 rb s3://cloudsentinel-dashboard-ACCOUNT_ID --profile myprofile

# 5. Delete SAM deploy bucket
aws s3 rm s3://cloudsentinel-deploy-ACCOUNT_ID --recursive --profile myprofile
aws s3 rb s3://cloudsentinel-deploy-ACCOUNT_ID --profile myprofile

# 6. (If you created CloudFront) Disable then delete:
# aws cloudfront get-distribution-config --id DISTRIBUTION_ID --profile myprofile
# Disable it in the console, wait for deployment, then delete
```

---

## Re-Deploy (After Tear Down)

```bash
# 1. Recreate deploy bucket
aws s3 mb s3://cloudsentinel-deploy-ACCOUNT_ID --profile myprofile

# 2. Build and deploy
sam build
sam deploy \
  --s3-bucket cloudsentinel-deploy-ACCOUNT_ID \
  --stack-name cloudsentinel \
  --profile myprofile \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Environment=dev AlertEmail=your@email.com

# 3. Update dashboard CONFIG with new outputs (ApiUrl, CognitoUserPoolId, CognitoClientId)
# 4. Recreate dashboard bucket and upload (see step 7 above)
# 5. Create Cognito user (see step 9 above)
```

---

## AWS Resources Created (~45 total)

| Service | Resources |
|---------|-----------|
| Lambda | 14 functions (simulators, detection, response, API, CloudTrail) |
| DynamoDB | 2 tables (events, alerts) with Streams + GSIs |
| API Gateway | 1 REST API with Cognito authorizer |
| Step Functions | 1 state machine (5-step IR workflow) |
| CloudTrail | 1 trail (write-only management events) |
| S3 | 3 buckets (incidents, CloudTrail logs, dashboard) |
| SNS | 1 topic + email subscription |
| EventBridge | 3 rules (attack schedule, critical alerts, CloudTrail) |
| Cognito | 1 User Pool + App Client |
| CloudFront | 1 distribution (optional, for HTTPS) |
| IAM | Roles and policies for all Lambda functions |

---

## Skills Demonstrated

- **Threat Detection & Incident Response** — MITRE ATT&CK framework, correlation rules, automated playbooks
- **Serverless Architecture** — Lambda, DynamoDB, API Gateway, Step Functions, EventBridge
- **Infrastructure as Code** — SAM/CloudFormation, single-command deploy
- **Real-Time Security Monitoring** — CloudTrail integration detecting actual AWS API activity
- **Workflow Orchestration** — Step Functions with branching logic, error handling, 5-stage IR pipeline
- **Authentication** — Cognito User Pool with JWT tokens, protected API endpoints
- **Event-Driven Design** — DynamoDB Streams, EventBridge rules, S3 triggers
- **Frontend** — Single-page dashboard with real-time data, filtering, detail panels

## License

MIT
