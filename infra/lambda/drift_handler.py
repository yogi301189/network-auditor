"""
drift_handler.py
────────────────────────────────────────────────────────────────
NetDevOps Self-Healing Platform — Drift Detection Lambda
Auditor Account (222892837737)

Flow:
  EventBridge (Config drift) → Lambda → CloudTrail lookup (WHO changed it)
                                      → Slack alert (what/who/when)
                                      → Auto-remediate via assume-role into Target
                                      → CloudWatch metric
"""

import boto3
import json
import logging
import os
import urllib.request
from datetime import datetime, timezone, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
SLACK_WEBHOOK_PARAM  = os.environ["SLACK_WEBHOOK_PARAM"]
TARGET_ACCOUNT_ID    = os.environ["TARGET_ACCOUNT_ID"]
REMEDIATION_ROLE_ARN = os.environ["REMEDIATION_ROLE_ARN"]
REGION               = os.environ.get("AWS_REGION_NAME", "eu-west-1")

# Map Config rule name → human-friendly label + auto-remediate flag
RULE_CONFIG = {
    "golden-rule-restricted-ssh": {
        "label": "Port 22 (SSH) open to world",
        "remediate": True,
        "handler": "remediate_security_group_port",
        "port": 22,
        "protocol": "tcp",
    },
    "golden-rule-restricted-rdp": {
        "label": "Port 3389 (RDP) open to world",
        "remediate": True,
        "handler": "remediate_security_group_port",
        "port": 3389,
        "protocol": "tcp",
    },
    "golden-rule-s3-no-public-read": {
        "label": "S3 bucket publicly readable",
        "remediate": True,
        "handler": "remediate_s3_public_access",
    },
    "golden-rule-s3-no-public-write": {
        "label": "S3 bucket publicly writable",
        "remediate": True,
        "handler": "remediate_s3_public_access",
    },
    "golden-rule-mfa-enabled": {
        "label": "IAM user missing MFA",
        "remediate": False,  # Cannot auto-remediate MFA — requires human action
        "handler": None,
    },
    "golden-rule-cloudtrail-enabled": {
        "label": "CloudTrail logging disabled",
        "remediate": True,
        "handler": "remediate_cloudtrail",
    },
    "golden-rule-root-no-access-keys": {
        "label": "Root account has active access keys",
        "remediate": False,  # Requires human — too sensitive to auto-touch
        "handler": None,
    },
    "golden-rule-rds-not-public": {
        "label": "RDS instance publicly accessible",
        "remediate": True,
        "handler": "remediate_rds_public",
    },
}


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────
def lambda_handler(event, context):
    logger.info("Drift event received: %s", json.dumps(event))

    detail      = event.get("detail", {})
    rule_name   = detail.get("configRuleName", "unknown-rule")
    resource_id = detail.get("resourceId", "unknown-resource")
    resource_type = detail.get("resourceType", "unknown-type")
    account_id  = detail.get("awsAccountId", TARGET_ACCOUNT_ID)
    timestamp   = event.get("time", datetime.now(timezone.utc).isoformat())

    rule_cfg    = RULE_CONFIG.get(rule_name, {
        "label": rule_name,
        "remediate": False,
        "handler": None
    })

    logger.info("Drift detected | Rule: %s | Resource: %s | Account: %s",
                rule_name, resource_id, account_id)

    # 1. Find WHO made the change via CloudTrail
    actor = lookup_cloudtrail_actor(resource_id, resource_type)

    # 2. Assume role in Target account for remediation
    target_session = assume_remediation_role()

    # 3. Auto-remediate if configured
    remediated = False
    remediation_detail = "N/A — manual action required"

    if rule_cfg.get("remediate") and rule_cfg.get("handler") and target_session:
        handler_fn = REMEDIATION_HANDLERS.get(rule_cfg["handler"])
        if handler_fn:
            try:
                remediation_detail = handler_fn(
                    target_session, resource_id, rule_cfg
                )
                remediated = True
                logger.info("Auto-remediated: %s", remediation_detail)
            except Exception as e:
                remediation_detail = f"Remediation failed: {str(e)}"
                logger.error(remediation_detail)

    # 4. Publish CloudWatch metric
    publish_metric(rule_name, remediated)

    # 5. Send Slack alert
    slack_webhook = get_slack_webhook()
    send_slack_alert(
        slack_webhook,
        rule_name      = rule_name,
        label          = rule_cfg["label"],
        resource_id    = resource_id,
        resource_type  = resource_type,
        account_id     = account_id,
        timestamp      = timestamp,
        actor          = actor,
        remediated     = remediated,
        remediation_detail = remediation_detail,
    )

    return {"statusCode": 200, "body": "Drift handled"}


# ─────────────────────────────────────────
# CLOUDTRAIL — Who changed it?
# ─────────────────────────────────────────
def lookup_cloudtrail_actor(resource_id: str, resource_type: str) -> dict:
    """
    Look back 15 minutes in CloudTrail for the last event touching this resource.
    Returns dict with actor name, time, and source IP.
    """
    try:
        ct = boto3.client("cloudtrail", region_name=REGION)
        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)

        response = ct.lookup_events(
            LookupAttributes=[{
                "AttributeKey":   "ResourceName",
                "AttributeValue": resource_id,
            }],
            StartTime = start_time,
            EndTime   = end_time,
            MaxResults = 5,
        )

        events = response.get("Events", [])
        if not events:
            return {"name": "Unknown (no CloudTrail event found)", "ip": "N/A", "time": "N/A"}

        latest = events[0]
        cloud_event = json.loads(latest.get("CloudTrailEvent", "{}"))

        actor_name = (
            cloud_event.get("userIdentity", {}).get("arn")
            or cloud_event.get("userIdentity", {}).get("userName")
            or "Unknown"
        )
        source_ip = cloud_event.get("sourceIPAddress", "N/A")
        event_time = latest.get("EventTime", "N/A")
        if hasattr(event_time, "isoformat"):
            event_time = event_time.isoformat()

        logger.info("CloudTrail actor: %s from %s at %s", actor_name, source_ip, event_time)
        return {"name": actor_name, "ip": source_ip, "time": str(event_time)}

    except Exception as e:
        logger.warning("CloudTrail lookup failed: %s", str(e))
        return {"name": "CloudTrail lookup failed", "ip": "N/A", "time": "N/A"}


# ─────────────────────────────────────────
# STS — Assume Role in Target Account
# ─────────────────────────────────────────
def assume_remediation_role():
    try:
        sts = boto3.client("sts")
        assumed = sts.assume_role(
            RoleArn         = REMEDIATION_ROLE_ARN,
            RoleSessionName = "DriftRemediationSession",
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id     = creds["AccessKeyId"],
            aws_secret_access_key = creds["SecretAccessKey"],
            aws_session_token     = creds["SessionToken"],
            region_name           = REGION,
        )
    except Exception as e:
        logger.error("Failed to assume remediation role: %s", str(e))
        return None


# ─────────────────────────────────────────
# REMEDIATION HANDLERS
# ─────────────────────────────────────────

def remediate_security_group_port(session, resource_id: str, rule_cfg: dict) -> str:
    """
    Revoke any ingress rule allowing the offending port from 0.0.0.0/0 or ::/0.
    This is the core drift fix: Terraform says 443 only, someone opened 22 → revoke it.
    """
    ec2 = session.client("ec2")
    port = rule_cfg["port"]
    protocol = rule_cfg["protocol"]

    # Get current security group rules
    response = ec2.describe_security_groups(GroupIds=[resource_id])
    sg = response["SecurityGroups"][0]

    revoked = []
    for rule in sg.get("IpPermissions", []):
        if rule.get("IpProtocol") != protocol:
            continue
        from_port = rule.get("FromPort", -1)
        to_port   = rule.get("ToPort", -1)

        # Check if this rule covers the offending port
        if not (from_port <= port <= to_port):
            continue

        # Find open-to-world CIDR entries
        open_ipv4 = [r for r in rule.get("IpRanges", [])  if r["CidrIp"]   == "0.0.0.0/0"]
        open_ipv6 = [r for r in rule.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]

        if open_ipv4 or open_ipv6:
            revoke_rule = {
                "IpProtocol": protocol,
                "FromPort":   from_port,
                "ToPort":     to_port,
            }
            if open_ipv4: revoke_rule["IpRanges"]   = open_ipv4
            if open_ipv6: revoke_rule["Ipv6Ranges"] = open_ipv6

            ec2.revoke_security_group_ingress(
                GroupId        = resource_id,
                IpPermissions  = [revoke_rule],
            )
            revoked.append(f"port {from_port}-{to_port}/{protocol} from 0.0.0.0/0")
            logger.info("Revoked rule: %s on %s", revoke_rule, resource_id)

    if revoked:
        return f"Revoked {', '.join(revoked)} on {resource_id}"
    return f"No open-world rule found for port {port} on {resource_id} (may already be fixed)"


def remediate_s3_public_access(session, resource_id: str, rule_cfg: dict) -> str:
    """Block all public access on the S3 bucket."""
    s3 = session.client("s3")
    s3.put_public_access_block(
        Bucket = resource_id,
        PublicAccessBlockConfiguration = {
            "BlockPublicAcls":       True,
            "IgnorePublicAcls":      True,
            "BlockPublicPolicy":     True,
            "RestrictPublicBuckets": True,
        }
    )
    return f"Public access block enforced on s3://{resource_id}"


def remediate_cloudtrail(session, resource_id: str, rule_cfg: dict) -> str:
    """Re-enable CloudTrail logging."""
    ct = session.client("cloudtrail")
    ct.start_logging(Name=resource_id)
    return f"CloudTrail logging re-enabled: {resource_id}"


def remediate_rds_public(session, resource_id: str, rule_cfg: dict) -> str:
    """Set RDS instance to not publicly accessible."""
    rds = session.client("rds")
    rds.modify_db_instance(
        DBInstanceIdentifier = resource_id,
        PubliclyAccessible   = False,
        ApplyImmediately     = True,
    )
    return f"RDS instance {resource_id} set to not publicly accessible"


# Handler dispatch table
REMEDIATION_HANDLERS = {
    "remediate_security_group_port": remediate_security_group_port,
    "remediate_s3_public_access":    remediate_s3_public_access,
    "remediate_cloudtrail":          remediate_cloudtrail,
    "remediate_rds_public":          remediate_rds_public,
}


# ─────────────────────────────────────────
# CLOUDWATCH — Publish Drift Metric
# ─────────────────────────────────────────
def publish_metric(rule_name: str, remediated: bool):
    cw = boto3.client("cloudwatch")
    cw.put_metric_data(
        Namespace  = "NetDevOps/DriftDetection",
        MetricData = [
            {
                "MetricName": "DriftDetected",
                "Dimensions": [{"Name": "Rule", "Value": rule_name}],
                "Value":      1,
                "Unit":       "Count",
            },
            *(
                [{
                    "MetricName": "DriftRemediated",
                    "Dimensions": [{"Name": "Rule", "Value": rule_name}],
                    "Value":      1,
                    "Unit":       "Count",
                }] if remediated else []
            ),
        ]
    )


# ─────────────────────────────────────────
# SSM — Get Slack Webhook
# ─────────────────────────────────────────
def get_slack_webhook() -> str:
    ssm = boto3.client("ssm", region_name=REGION)
    response = ssm.get_parameter(Name=SLACK_WEBHOOK_PARAM, WithDecryption=True)
    return response["Parameter"]["Value"]


# ─────────────────────────────────────────
# SLACK — Send Alert
# ─────────────────────────────────────────
def send_slack_alert(
    webhook_url: str,
    rule_name: str,
    label: str,
    resource_id: str,
    resource_type: str,
    account_id: str,
    timestamp: str,
    actor: dict,
    remediated: bool,
    remediation_detail: str,
):
    status_emoji  = "✅" if remediated else "⚠️"
    status_text   = "Auto-Remediated" if remediated else "Manual Action Required"
    color         = "#36a64f" if remediated else "#ff0000"

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{status_emoji} Drift Detected — {label}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Rule:*\n`{rule_name}`"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{status_text}"},
                        {"type": "mrkdwn", "text": f"*Resource:*\n`{resource_id}`"},
                        {"type": "mrkdwn", "text": f"*Type:*\n{resource_type}"},
                        {"type": "mrkdwn", "text": f"*Account:*\n`{account_id}`"},
                        {"type": "mrkdwn", "text": f"*Detected At:*\n{timestamp}"},
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Changed By:*\n`{actor.get('name', 'Unknown')}`"},
                        {"type": "mrkdwn", "text": f"*Source IP:*\n`{actor.get('ip', 'N/A')}`"},
                        {"type": "mrkdwn", "text": f"*Change Time:*\n{actor.get('time', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Remediation:*\n{remediation_detail}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": "🔒 NetDevOps Self-Healing Platform | Drift Detection"
                    }]
                }
            ]
        }]
    }

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        webhook_url,
        data    = data,
        headers = {"Content-Type": "application/json"},
        method  = "POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        logger.info("Slack response: %s", resp.status)
