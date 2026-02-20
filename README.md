# Network Auditor
> A production-grade, self-healing AWS network security platform built with Python, Terraform, and GitHub Actions.

---

## What It Does

Network Auditor continuously monitors your AWS account for security misconfigurations and cost hygiene violations. It operates in two modes:

**Daily Mode** — scans every AWS region every morning at 06:00 UTC and produces a prioritised report of all violations found.

**Real-time Mode** — detects dangerous Security Group changes within seconds of them happening, automatically removes the offending rule, and posts a Slack alert with full context.

No human intervention required. The network heals itself.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DAILY AUDITOR                            │
│                                                                 │
│  GitHub Actions (06:00 UTC)                                     │
│       │                                                         │
│       ▼                                                         │
│  auditor/main.py ──► checks.py (5 Golden Rules)                 │
│       │                                                         │
│       ▼                                                         │
│  report.py ──► findings.json + summary.md ──► Git commit        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    REAL-TIME SELF-HEALING                        │
│                                                                 │
│  EC2 Console change                                             │
│       │ (seconds)                                               │
│       ▼                                                         │
│  CloudTrail ──► EventBridge ──► Lambda (handler.py)             │
│                                     │                           │
│                          ┌──────────┼──────────┐               │
│                          ▼          ▼           ▼               │
│                    Revoke rule   CloudWatch   Slack alert        │
│                    (boto3)       metrics      #social            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    CLOUDWATCH DASHBOARD                          │
│                                                                 │
│  Violations over time  │  Remediation outcomes                  │
│  Total violations      │  Total auto-remediated                 │
│  Recent violation log (live Logs Insights table)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Golden Rules

| # | Rule | Severity | What It Checks |
|---|------|----------|----------------|
| 1 | `required_vpc_tags` | WARNING | VPCs missing Owner, Environment, CostCenter, or Project tags |
| 2 | `no_open_ssh_rdp` | CRITICAL | Security Groups allowing 0.0.0.0/0 on port 22 or 3389 |
| 3 | `no_public_rds` | CRITICAL | RDS instances with PubliclyAccessible = True |
| 4 | `no_orphaned_eips` | WARNING | Elastic IPs allocated but not attached to any resource |
| 5 | `no_public_s3_buckets` | CRITICAL | S3 buckets with Block Public Access disabled |

---

## Project Structure

```
network-auditor/
│
├── auditor/                      Daily scan engine
│   ├── __init__.py               Makes auditor a Python package
│   ├── main.py                   Entry point — orchestrates scan across all regions
│   ├── checks.py                 One function per Golden Rule
│   └── report.py                 Formats findings → JSON + Markdown
│
├── infra/                        Real-time self-healing layer (Terraform)
│   ├── main.tf                   Lambda + EventBridge + IAM + Dashboard
│   ├── variables.tf              Input variables (region, Slack webhook)
│   ├── terraform.tfvars.example  Template — copy to terraform.tfvars
│   └── lambda/
│       └── handler.py            Real-time detector + auto-remediation
│
├── setup/
│   └── iam_setup.sh              IAM policy + OIDC setup reference
│
├── reports/                      Scan outputs (git-tracked, auto-committed)
│   ├── findings_*.json           Machine-readable full findings
│   └── summary_*.md              Human-readable Markdown summary
│
├── tag_default_vpcs.py           One-shot script to tag all default VPCs
├── requirements.txt              Python dependencies (boto3 only)
├── .gitignore                    Excludes tfvars, state, zips, pycache
└── README.md                     This file
```

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.12 | Auditor logic, Lambda handler |
| AWS SDK | boto3 | All AWS API calls |
| Infrastructure | Terraform | Lambda, EventBridge, IAM, Dashboard |
| CI/CD | GitHub Actions | Daily automated scan pipeline |
| Auth | AWS OIDC | Keyless GitHub to AWS authentication |
| Events | AWS EventBridge | Real-time Security Group change detection |
| Compute | AWS Lambda | Serverless violation detector |
| Observability | AWS CloudWatch | Logs, metrics, dashboard |
| Alerting | Slack Webhooks | Instant team notification |

---

## Setup Guide

### Prerequisites
- AWS account (free tier is sufficient)
- GitHub account
- Python 3.12+
- Terraform 1.5+
- AWS CLI configured

---

### Part 1 — Daily Auditor

**Step 1 — Clone and install**
```bash
git clone https://github.com/YOUR_USERNAME/network-auditor.git
cd network-auditor
pip install -r requirements.txt
```

**Step 2 — Create the IAM Policy**

AWS Console → IAM → Policies → Create policy → JSON:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeRegions",
      "ec2:DescribeVpcs",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeAddresses",
      "ec2:DescribeSubnets",
      "ec2:CreateTags",
      "rds:DescribeDBInstances",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock"
    ],
    "Resource": "*"
  }]
}
```
Name: `NetworkAuditorPolicy`

**Step 3 — Register GitHub as OIDC provider**

AWS Console → IAM → Identity providers → Add provider:
- Type: OpenID Connect
- URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

**Step 4 — Create IAM Role**

Create role `NetworkAuditorRole` with trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:YOUR_GH_USERNAME/network-auditor:ref:refs/heads/main"
      }
    }
  }]
}
```

**Step 5 — Add GitHub Secret**

Repo → Settings → Secrets → New secret:
- Name: `AWS_AUDIT_ROLE_ARN`
- Value: `arn:aws:iam::YOUR_ACCOUNT_ID:role/NetworkAuditorRole`

**Step 6 — Push and run**
```bash
git push origin main
# Actions tab → Network Audit → Run workflow
```

---

### Part 2 — Real-time Self-Healing

**Step 1 — Enable CloudTrail** (required for EventBridge)

AWS Console → CloudTrail → Create trail → all regions.

**Step 2 — Set up Slack webhook**

https://api.slack.com/apps → Create app → Incoming Webhooks → Add to channel → copy URL.

**Step 3 — Deploy with Terraform**
```bash
cd infra/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — add your Slack webhook URL

terraform init
terraform plan
terraform apply
```

**Step 4 — Verify**

Add SSH `0.0.0.0/0` to any Security Group. Within 30 seconds:
- Rule is automatically removed
- Slack alert fires with full context and direct fix link
- CloudWatch logs show `[REMEDIATED]`
- Dashboard metrics update

---

## Running Locally

```bash
# Full scan
python -m auditor.main

# Tag all default VPCs
python tag_default_vpcs.py

# View reports
ls reports/
```

---

## Adding a New Golden Rule

1. Write the function in `checks.py`:
```python
def find_your_rule(region: str) -> list[dict]:
    findings = []
    # ... boto3 logic ...
    findings.append(_finding(
        severity="CRITICAL", rule="your_rule",
        resource_id=resource_id, region=region,
        detail="What is wrong and why",
    ))
    return findings
```

2. Register it in `main.py`:
```python
GOLDEN_RULES = [
    ...
    checks.find_your_rule,  # add here
]
```

3. Add the required IAM permission to `NetworkAuditorPolicy`.

The rule runs automatically across all regions on the next scan.

---

## Tearing Down

```bash
cd infra/
terraform destroy   # removes Lambda, EventBridge, IAM, Dashboard
```

GitHub Actions daily scan is unaffected.

---

## Cost

Runs entirely within AWS and GitHub free tiers.

| Resource | Monthly cost |
|---|---|
| GitHub Actions | $0 (under 2,000 min/month) |
| Lambda | $0 (under 1M invocations/month) |
| EventBridge | $0 (under 1M events/month) |
| CloudWatch Dashboard | $0 (1 dashboard free) |
| CloudWatch Logs | $0 (under 5GB/month) |
| CloudTrail S3 | ~$0.01 — set 7-day lifecycle rule |

---

## What This Project Demonstrates

- **NetDevOps** — network infrastructure managed as code, not tickets
- **Python + boto3** — cross-region AWS automation built from scratch
- **Terraform IaC** — Lambda, EventBridge, IAM, and Dashboards as code
- **GitHub Actions CI/CD** — automated pipeline with OIDC auth
- **Event-driven architecture** — CloudTrail → EventBridge → Lambda
- **Self-healing infrastructure** — autonomous detection and remediation
- **Least-privilege IAM** — every role has exactly the permissions it needs
- **Observability** — structured metrics, logs, and a live dashboard

---

*Built as part of the NetDevOps Migration and Modernization project — 2026.*c