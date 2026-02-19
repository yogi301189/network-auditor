# Adding a New AWS Account to Network Auditor

This guide covers everything needed to onboard a new AWS account
into the multi-account scanning and real-time self-healing platform.

**Time required:** ~15 minutes  
**Prerequisites:** Access to both the new AWS account and the auditor GitHub repo

---

## Overview

When a new account is onboarded, it gets:
- ✅ Daily scan coverage (included in the 6am report automatically)
- ✅ Real-time Security Group violation detection
- ✅ Auto-remediation (bad rules removed within seconds)
- ✅ Slack alerts tagged with the account name

---

## Step 1 — Enable CloudTrail in the New Account

EventBridge cannot detect API calls without CloudTrail active.

> Login to new account → CloudTrail → **Create trail**
> - Trail name: `network-auditor-trail`
> - Apply to all regions: **Yes**
> - S3 bucket: let AWS create automatically
> - Click **Create**

Wait 2-3 minutes for CloudTrail to activate before proceeding.

---

## Step 2 — Create the Auditor Role in the New Account

> IAM → Roles → **Create role** → Custom trust policy

**Trust policy** — allows the Auditor account's Lambda to assume this role:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": [
        "arn:aws:iam::222892837737:root",
        "arn:aws:iam::222892837737:role/NetworkAuditorLambdaRole"
      ]
    },
    "Action": "sts:AssumeRole"
  }]
}
```

Click **Next** → Create inline policy with these permissions:
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
      "ec2:DescribeVolumes",
      "ec2:DescribeInstances",
      "ec2:RevokeSecurityGroupIngress",
      "rds:DescribeDBInstances",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration"
    ],
    "Resource": "*"
  }]
}
```

> Role name: `NetworkAuditorTargetRole` → **Create role**

Note the new account ID — you'll need it in the next steps.

---

## Step 3 — Update `accounts.json`

Add the new account to the daily scan list:

```json
[
  {
    "account_id": "222892837737",
    "account_name": "Auditor (Primary)",
    "role_arn": null,
    "notes": "Home account — scanned directly"
  },
  {
    "account_id": "278119224464",
    "account_name": "Target (Secondary)",
    "role_arn": "arn:aws:iam::278119224464:role/NetworkAuditorTargetRole",
    "notes": "Target account"
  },
  {
    "account_id": "NEW_ACCOUNT_ID",
    "account_name": "Your Account Name Here",
    "role_arn": "arn:aws:iam::NEW_ACCOUNT_ID:role/NetworkAuditorTargetRole",
    "notes": "Brief description e.g. Production, Staging, Dev"
  }
]
```

---

## Step 4 — Update `infra/lambda/handler.py`

Add the new account to the `ACCOUNT_ROLES` map so the Lambda
knows which role to assume for real-time remediation:

```python
ACCOUNT_ROLES = {
    "278119224464": "arn:aws:iam::278119224464:role/NetworkAuditorTargetRole",
    "NEW_ACCOUNT_ID": "arn:aws:iam::NEW_ACCOUNT_ID:role/NetworkAuditorTargetRole",
}
```

---

## Step 5 — Update `infra/main.tf` Event Bus Policy

Add the new account to the central Event Bus policy so it can
forward events to Account A:

```hcl
resource "aws_cloudwatch_event_bus_policy" "allow_target_accounts" {
  ...
  policy = jsonencode({
    Statement = [{
      Principal = {
        AWS = [
          "arn:aws:iam::278119224464:root",
          "arn:aws:iam::NEW_ACCOUNT_ID:root",   # ← add this line
        ]
      }
      ...
    }]
  })
}
```

Also add the new account's forwarding rule in `infra/account_b.tf`
(or create a new `account_c.tf` for clarity):

```hcl
provider "aws" {
  alias  = "account_c"
  region = var.aws_region
  assume_role {
    role_arn     = "arn:aws:iam::NEW_ACCOUNT_ID:role/NetworkAuditorTargetRole"
    session_name = "TerraformNetworkAuditor"
  }
}

resource "aws_cloudwatch_event_rule" "account_c_sg_forward" {
  provider    = aws.account_c
  name        = "NetworkAuditorForwardSGChanges"
  description = "Forwards SG changes to Account A central Event Bus"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"] }
  })
}

resource "aws_cloudwatch_event_target" "account_c_forward" {
  provider = aws.account_c
  rule     = aws_cloudwatch_event_rule.account_c_sg_forward.name
  arn      = aws_cloudwatch_event_bus.central.arn
  role_arn = aws_iam_role.account_c_eventbridge_role.arn
}

resource "aws_iam_role" "account_c_eventbridge_role" {
  provider = aws.account_c
  name     = "NetworkAuditorEventBridgeForwardRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "account_c_eventbridge_policy" {
  provider = aws.account_c
  name     = "NetworkAuditorEventBridgeForwardPolicy"
  role     = aws_iam_role.account_c_eventbridge_role.id
  policy   = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["events:PutEvents"], Resource = aws_cloudwatch_event_bus.central.arn }]
  })
}
```

---

## Step 6 — Deploy and Push

```bash
# Deploy infrastructure changes
cd infra/
terraform apply

# Commit and push code changes
cd ..
git add accounts.json infra/lambda/handler.py infra/main.tf
git commit -m "feat: onboard NEW_ACCOUNT_ID (Your Account Name) to Network Auditor"
git pull origin main --rebase
git push
```

---

## Step 7 — Verify

**Test daily scan:**
> GitHub Actions → Network Audit → Run workflow

The report should show the new account's findings tagged with its name.

**Test real-time detection:**
> New account → EC2 → Security Groups → add SSH `0.0.0.0/0`

Within 30 seconds:
- Bad rule is automatically removed
- Slack alert fires showing the account name
- CloudWatch logs show `account=NEW_ACCOUNT_ID remediated=True`

---

## Onboarding Checklist

```
□ CloudTrail enabled in new account (all regions)
□ NetworkAuditorTargetRole created in new account
□ Trust policy allows 222892837737 root + LambdaRole
□ accounts.json updated
□ handler.py ACCOUNT_ROLES updated
□ main.tf Event Bus policy updated
□ New account Terraform forwarding rule added
□ terraform apply run successfully
□ Code committed and pushed
□ Daily scan verified
□ Real-time detection verified
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| AccessDenied on AssumeRole | Lambda role missing sts:AssumeRole | Add to NetworkAuditorLambdaRole inline policy |
| SG not found error | Lambda using wrong account credentials | Check ACCOUNT_ROLES map in handler.py |
| No real-time events | CloudTrail not enabled | Enable CloudTrail in new account |
| No forwarding rule in new account | Terraform provider missing | Add account provider block to Terraform |
| UnauthorizedOperation on Revoke | Missing ec2:RevokeSecurityGroupIngress | Add to NetworkAuditorTargetRole policy |

---

*Network Auditor — NetDevOps Migration & Modernization Project — 2026*