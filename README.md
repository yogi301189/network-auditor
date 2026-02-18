# Network Auditor

Scans your AWS account daily for Shadow IT, security misconfigurations,
and cost hygiene violations. Read-only — never modifies anything.

## Golden Rules enforced

| Rule | Severity | What it checks |
|---|---|---|
| `required_vpc_tags` | WARNING | VPCs missing Owner, Environment, CostCenter, or Project tags |
| `no_open_ssh_rdp` | CRITICAL | Security Groups allowing 0.0.0.0/0 on port 22 or 3389 |
| `no_public_rds` | CRITICAL | RDS instances with PubliclyAccessible = True |
| `no_orphaned_eips` | WARNING | Elastic IPs allocated but not attached to any resource |

---

## Setup (one-time, ~15 minutes)

### Step 1 — Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/network-auditor.git
cd network-auditor
pip install -r requirements.txt
```

### Step 2 — Create the AWS IAM Role for the auditor

The auditor needs read-only access to EC2, RDS, and a few other services.
Create this policy in AWS IAM:

**Policy name:** `NetworkAuditorPolicy`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeAddresses",
        "ec2:DescribeSubnets",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to a new IAM Role named `NetworkAuditorRole`.

### Step 3 — Connect GitHub Actions to AWS (OIDC — no API keys needed)

This is the secure way. GitHub proves its identity to AWS directly,
so you never store long-lived credentials anywhere.

1. In AWS IAM → Identity Providers → Add Provider
   - Type: OpenID Connect
   - URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`

2. Edit the Trust Policy of `NetworkAuditorRole` to allow GitHub Actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:YOUR_USERNAME/network-auditor:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

Replace `YOUR_ACCOUNT_ID` and `YOUR_USERNAME` with your actual values.

3. In your GitHub repo → Settings → Secrets → New repository secret:
   - Name: `AWS_AUDIT_ROLE_ARN`
   - Value: `arn:aws:iam::YOUR_ACCOUNT_ID:role/NetworkAuditorRole`

### Step 4 — (Optional) Add Slack notifications

1. In Slack: Apps → Incoming Webhooks → Add to channel → copy the webhook URL
2. In GitHub repo → Settings → Secrets → New repository secret:
   - Name: `SLACK_WEBHOOK_URL`
   - Value: the webhook URL from Slack

If you skip this, the workflow still runs — it just won't post to Slack.

---

## Running locally

```bash
# Make sure AWS credentials are configured
aws configure

# Run the scan
python -m auditor.main

# Reports are saved to reports/
ls reports/
```

## Project structure

```
network-auditor/
├── auditor/
│   ├── __init__.py    — makes auditor a Python package
│   ├── main.py        — entry point, orchestrates the scan
│   ├── checks.py      — one function per Golden Rule
│   └── report.py      — formats findings into JSON + Markdown
├── reports/           — scan output lives here (git-tracked)
├── .github/
│   └── workflows/
│       └── audit.yml  — GitHub Actions: runs daily at 06:00 UTC
└── requirements.txt
```

## Adding a new Golden Rule

1. Write a new function in `checks.py` following the same contract:
   - Input: `region: str`
   - Output: `list[dict]` (use the `_finding()` helper)

2. Add the function to `GOLDEN_RULES` in `main.py`:
   ```python
   GOLDEN_RULES = [
       checks.find_untagged_vpcs,
       checks.find_open_ssh_rdp,
       checks.find_public_rds,
       checks.find_orphaned_eips,
       checks.your_new_rule,    # ← add here
   ]
   ```

That's it. The new rule runs automatically in every region on the next scan.