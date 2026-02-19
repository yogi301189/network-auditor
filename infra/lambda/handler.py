"""
infra/lambda/handler.py
========================
Real-time Security Group violation detector.

Triggered by EventBridge whenever anyone modifies a Security Group
inbound rule in AWS. Checks if the change violates a Golden Rule.
If it does, posts an immediate alert to Slack.

This function is READ-ONLY for now (alert mode).
It detects and reports — humans fix.
"""

import json
import os
import urllib.request
import urllib.error
import boto3
from datetime import datetime, timezone


# ── ACCOUNT ROLE MAP ──────────────────────────────────────────────────────────
# Maps target account IDs to their auditor role ARNs.
# When an event arrives from Account B, Lambda assumes this role
# to fetch the Security Group details from Account B.
# Add new accounts here as you onboard them.

ACCOUNT_ROLES = {
    "278119224464": "arn:aws:iam::278119224464:role/NetworkAuditorTargetRole",
    # "ACCOUNT_C_ID": "arn:aws:iam::ACCOUNT_C_ID:role/NetworkAuditorTargetRole",
}

# This Lambda's own account ID — no role assumption needed for home account
HOME_ACCOUNT = os.environ.get("HOME_ACCOUNT_ID", "222892837737")


def get_ec2_client_for_account(account_id: str, region: str):
    """
    Returns an EC2 client for the correct account.
    For the home account — uses Lambda's own credentials directly.
    For target accounts — assumes their NetworkAuditorTargetRole via STS.
    """
    if account_id == HOME_ACCOUNT or account_id not in ACCOUNT_ROLES:
        return boto3.client("ec2", region_name=region)

    role_arn = ACCOUNT_ROLES[account_id]
    sts = boto3.client("sts")

    try:
        response = sts.assume_role(
            RoleArn         = role_arn,
            RoleSessionName = f"NetworkAuditorHandler-{account_id}",
            DurationSeconds = 900,  # 15 minutes — enough for one remediation
        )
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id     = creds["AccessKeyId"],
            aws_secret_access_key = creds["SecretAccessKey"],
            aws_session_token     = creds["SessionToken"],
        )
        return session.client("ec2", region_name=region)

    except Exception as e:
        print(f"[ERROR] Could not assume role for account {account_id}: {e}")
        return boto3.client("ec2", region_name=region)


# ── CLOUDWATCH METRICS ────────────────────────────────────────────────────────

def publish_metric(metric_name: str, value: float, unit: str = "Count", dimensions: list = []) -> None:
    """
    Publishes a custom metric to CloudWatch under the 'NetworkAuditor' namespace.
    These metrics power the dashboard widgets.

    metric_name : e.g. "ViolationDetected", "RemediationSuccess"
    value       : numeric value (usually 1.0 for event counting)
    unit        : CloudWatch unit string
    dimensions  : list of {"Name": ..., "Value": ...} dicts for filtering
    """
    cw = boto3.client("cloudwatch", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    try:
        cw.put_metric_data(
            Namespace="NetworkAuditor",
            MetricData=[{
                "MetricName": metric_name,
                "Value":      value,
                "Unit":       unit,
                "Timestamp":  datetime.now(timezone.utc),
                "Dimensions": dimensions,
            }]
        )
        print(f"[METRIC] Published {metric_name}={value}")
    except Exception as e:
        print(f"[ERROR] Failed to publish metric {metric_name}: {e}")


# ── GOLDEN RULES ──────────────────────────────────────────────────────────────
# Ports that must never be open to the entire internet.
# Mirrors the logic in auditor/checks.py — single source of truth
# will be merged in a future refactor.

DANGEROUS_PORTS = {22, 3389}
OPEN_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


# ── SLACK ALERTER ─────────────────────────────────────────────────────────────

def post_to_slack(message: str) -> None:
    """
    Posts a message to Slack via Incoming Webhook.
    The webhook URL is injected as an environment variable by Terraform.
    Fails silently if the webhook isn't configured — Lambda still succeeds.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")

    if not webhook_url:
        print("[WARN] SLACK_WEBHOOK_URL not set — skipping Slack notification")
        return

    payload = json.dumps({"text": message}).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"[INFO] Slack notified — HTTP {resp.status}")
    except urllib.error.URLError as e:
        print(f"[ERROR] Slack notification failed: {e}")


# ── VIOLATION CHECKER ─────────────────────────────────────────────────────────

def is_dangerous_rule(ip_permission: dict) -> tuple[bool, list[int]]:
    """
    Checks a single inbound rule for open-world access on dangerous ports.

    Returns:
        (is_dangerous, list_of_exposed_ports)

    Example:
        rule allows 0.0.0.0/0 on port range 0-65535
        → (True, [22, 3389])
    """
    from_port = ip_permission.get("FromPort", -1)
    to_port   = ip_permission.get("ToPort",   -1)

    # Find dangerous ports within this rule's range
    exposed = [p for p in DANGEROUS_PORTS if from_port <= p <= to_port]
    if not exposed:
        return False, []

    # Check for open-world IPv4 or IPv6
    ipv4_open = any(
        r.get("CidrIp") in OPEN_WORLD_CIDRS
        for r in ip_permission.get("IpRanges", [])
    )
    ipv6_open = any(
        r.get("CidrIpv6") in OPEN_WORLD_CIDRS
        for r in ip_permission.get("Ipv6Ranges", [])
    )

    return (ipv4_open or ipv6_open), exposed


def get_sg_details(sg_id: str, region: str, account_id: str) -> dict:
    """
    Fetches the current state of the Security Group from the correct account.
    Uses cross-account role assumption for target accounts.
    """
    ec2 = get_ec2_client_for_account(account_id, region)
    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        return response["SecurityGroups"][0] if response["SecurityGroups"] else {}
    except Exception as e:
        print(f"[ERROR] Could not fetch SG {sg_id}: {e}")
        return {}


# ── AUTO-REMEDIATION ─────────────────────────────────────────────────────────

def revoke_bad_rule(sg_id: str, rule: dict, region: str, account_id: str) -> bool:
    """
    Removes the specific offending inbound rule from the Security Group
    in the correct account using cross-account role assumption.
    """
    ec2 = get_ec2_client_for_account(account_id, region)
    try:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[rule],
        )
        print(f"[REMEDIATED] Removed bad rule from {sg_id} in account {account_id}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to remove rule from {sg_id}: {e}")
        return False


# ── ALERT BUILDER ─────────────────────────────────────────────────────────────

def build_alert_message(sg: dict, exposed_ports: list[int], region: str, remediated: bool) -> str:
    """
    Builds a clear, actionable Slack alert message.
    Shows whether the rule was automatically removed or needs manual action.
    """
    sg_id   = sg.get("GroupId", "unknown")
    sg_name = sg.get("GroupName", "unnamed")
    port_str = " and ".join(
        "SSH (port 22)" if p == 22 else "RDP (port 3389)"
        for p in sorted(exposed_ports)
    )
    console_url = (
        f"https://{region}.console.aws.amazon.com/ec2/v2/home"
        f"?region={region}#SecurityGroups:group-id={sg_id}"
    )

    if remediated:
        status_line = ":white_check_mark: *Auto-remediated — bad rule automatically removed*"
        action_line = "Verify the fix looks correct and investigate who made the change."
    else:
        status_line = ":x: *Auto-remediation failed — manual action required*"
        action_line = "Remove the 0.0.0.0/0 inbound rule immediately."

    return (
        f":rotating_light: *Security Group Violation Detected*\n"
        f">{status_line}\n"
        f">*Security Group:* `{sg_id}` ({sg_name})\n"
        f">*Region:* `{region}`\n"
        f">*Exposed:* {port_str} open to the entire internet\n"
        f">*Action:* {action_line}\n"
        f">*Review here:* {console_url}"
    )


# ── MAIN HANDLER ──────────────────────────────────────────────────────────────

def lambda_handler(event: dict, context) -> dict:
    """
    Entry point — called by AWS Lambda when EventBridge fires.

    EventBridge sends us an event every time a Security Group rule
    is added or modified. We check it and alert if it's dangerous.
    """
    print(f"[INFO] Event received: {json.dumps(event)}")

    # ── Extract key fields from the EventBridge event ──
    detail     = event.get("detail", {})
    region     = event.get("region", "unknown")
    account_id = event.get("account", HOME_ACCOUNT)  # which account the event came from

    print(f"[INFO] Event from account: {account_id} region: {region}")

    # The API call that triggered this event
    event_name = detail.get("eventName", "")

    # We only care about rule additions — not deletions or other changes
    if event_name not in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
        print(f"[INFO] Event '{event_name}' is not a rule addition — skipping")
        return {"status": "skipped", "reason": f"event type {event_name} not monitored"}

    # ── Extract the Security Group ID ──
    request_params = detail.get("requestParameters", {})

    # The SG ID field name differs slightly between event types
    sg_id = (
        request_params.get("groupId")
        or request_params.get("ModifySecurityGroupRulesRequest", {}).get("GroupId")
    )

    if not sg_id:
        print("[WARN] Could not extract Security Group ID from event")
        return {"status": "error", "reason": "no sg_id found"}

    print(f"[INFO] Checking Security Group: {sg_id} in {region}")

    # ── Fetch live SG state and check all inbound rules ──
    sg = get_sg_details(sg_id, region, account_id)
    if not sg:
        return {"status": "error", "reason": f"could not fetch {sg_id}"}

    violations_found = False

    for rule in sg.get("IpPermissions", []):
        dangerous, exposed_ports = is_dangerous_rule(rule)

        if dangerous:
            violations_found = True
            print(f"[ALERT] Violation detected on {sg_id} in account {account_id} — ports {exposed_ports}")

            publish_metric(
                metric_name = "ViolationDetected",
                value       = 1.0,
                dimensions  = [
                    {"Name": "Rule",      "Value": "no_open_ssh_rdp"},
                    {"Name": "Region",    "Value": region},
                    {"Name": "AccountId", "Value": account_id},
                ]
            )

            remediated = revoke_bad_rule(sg_id, rule, region, account_id)

            publish_metric(
                metric_name = "RemediationSuccess" if remediated else "RemediationFailed",
                value       = 1.0,
                dimensions  = [
                    {"Name": "Region",    "Value": region},
                    {"Name": "AccountId", "Value": account_id},
                ]
            )

            message = build_alert_message(sg, exposed_ports, region, remediated)
            post_to_slack(message)

            print(f"[VIOLATION] sg={sg_id} account={account_id} region={region} ports={exposed_ports} remediated={remediated}")

    if not violations_found:
        print(f"[INFO] {sg_id} — no violations found in current state")

    return {
        "status": "ok",
        "sg_id": sg_id,
        "violation": violations_found,
    }