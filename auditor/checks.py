"""
Network Auditor — checks.py
============================
This file contains one function per Golden Rule.
Every function follows the exact same contract:

    Input:  a region name (string)  e.g. "us-east-1"
    Output: a list of findings      e.g. [{"severity": "CRITICAL", ...}]

If the list is empty → no violations found in that region. ✓
If the list has items → each item is one specific resource that broke the rule.

The functions never print, never modify AWS resources, and never raise exceptions
intentionally. main.py handles errors at the call site.
"""

import boto3


# ── SHARED HELPER ─────────────────────────────────────────────────────────────

def _finding(severity: str, rule: str, resource_id: str, region: str, detail: str) -> dict:
    """
    Builds a standard finding dictionary. Every check uses this helper
    so all findings have exactly the same shape — important for report.py.

    severity  : "CRITICAL" or "WARNING"
    rule      : snake_case name of the rule that fired, e.g. "no_open_ssh"
    resource_id: the AWS resource ID, e.g. "sg-0abc1234"
    region    : AWS region string, e.g. "us-east-1"
    detail    : human-readable explanation of what's wrong
    """
    return {
        "severity":    severity,
        "rule":        rule,
        "resource_id": resource_id,
        "region":      region,
        "detail":      detail,
    }


# ── GOLDEN RULE 1: UNTAGGED VPCs ─────────────────────────────────────────────
#
# Rule: Every VPC must have all four required tags.
# Why:  Untagged VPCs are "Shadow IT" — no owner, no cost attribution,
#       no idea if they're needed. They accumulate silently and create risk.

REQUIRED_TAGS = {"Owner", "Environment", "CostCenter", "Project"}

def find_untagged_vpcs(region: str) -> list[dict]:
    """
    Scans all VPCs in the region and flags any that are missing
    one or more of the REQUIRED_TAGS defined above.
    """
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    # describe_vpcs() returns ALL VPCs, including the default VPC AWS creates.
    # We include the default VPC deliberately — it's often left unmanaged.
    response = ec2.describe_vpcs()

    for vpc in response["Vpcs"]:
        vpc_id = vpc["VpcId"]

        # AWS returns tags as a list of {"Key": "...", "Value": "..."} dicts.
        # We convert it to a plain set of key names for easy comparison.
        existing_tags = {tag["Key"] for tag in vpc.get("Tags", [])}

        # Set difference: which required tags are NOT present?
        missing = REQUIRED_TAGS - existing_tags

        if missing:
            findings.append(_finding(
                severity    = "WARNING",
                rule        = "required_vpc_tags",
                resource_id = vpc_id,
                region      = region,
                detail      = f"Missing required tags: {', '.join(sorted(missing))}",
            ))

    return findings


# ── GOLDEN RULE 2: OPEN SSH / RDP ─────────────────────────────────────────────
#
# Rule: No Security Group may allow inbound traffic from the entire internet
#       (0.0.0.0/0 or ::/0) on port 22 (SSH) or port 3389 (RDP).
# Why:  These are the two most commonly brute-forced ports on the internet.
#       Any open rule here is an active attack surface — severity is CRITICAL.

DANGEROUS_PORTS = {22, 3389}

def find_open_ssh_rdp(region: str) -> list[dict]:
    """
    Scans all Security Group inbound rules and flags any that permit
    unrestricted internet access on SSH or RDP ports.
    """
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    # We request all security groups in this region in one API call.
    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        sg_id   = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")

        # IpPermissions is the list of inbound rules for this security group.
        for rule in sg.get("IpPermissions", []):

            # FromPort/ToPort define the port range for this rule.
            # Some rules (e.g. ICMP) have no port — we skip those safely.
            from_port = rule.get("FromPort", -1)
            to_port   = rule.get("ToPort",   -1)

            # A rule covers a range (e.g. 0-65535). We check if any dangerous
            # port falls within that range.
            exposed_ports = [
                p for p in DANGEROUS_PORTS
                if from_port <= p <= to_port
            ]

            if not exposed_ports:
                continue  # This rule doesn't touch SSH or RDP — skip it.

            # Check for IPv4 open-world access: 0.0.0.0/0
            ipv4_open = any(
                r.get("CidrIp") == "0.0.0.0/0"
                for r in rule.get("IpRanges", [])
            )

            # Check for IPv6 open-world access: ::/0
            ipv6_open = any(
                r.get("CidrIpv6") == "::/0"
                for r in rule.get("Ipv6Ranges", [])
            )

            if ipv4_open or ipv6_open:
                protocol = "IPv4" if ipv4_open else "IPv6"
                port_str = ", ".join(f"port {p}" for p in sorted(exposed_ports))
                findings.append(_finding(
                    severity    = "CRITICAL",
                    rule        = "no_open_ssh_rdp",
                    resource_id = sg_id,
                    region      = region,
                    detail      = f"SG '{sg_name}' allows {protocol} 0.0.0.0/0 on {port_str}",
                ))

    return findings


# ── GOLDEN RULE 3: RDS IN PUBLIC SUBNETS ─────────────────────────────────────
#
# Rule: No RDS database instance may be publicly accessible.
# Why:  A database exposed to the internet is a catastrophic data breach risk.
#       AWS actually has a "PubliclyAccessible" flag on RDS — we check it directly.

def find_public_rds(region: str) -> list[dict]:
    """
    Scans all RDS instances and flags any where PubliclyAccessible is True.
    This is the AWS-native flag that controls whether the DB gets a
    public DNS endpoint — it's the clearest signal of misconfiguration.
    """
    findings = []

    try:
        rds = boto3.client("rds", region_name=region)
        # describe_db_instances() returns all RDS instances in the region.
        response = rds.describe_db_instances()

    except rds.exceptions.ClientError:
        # RDS may not be available or have instances in every region — that's fine.
        return findings

    for db in response["DBInstances"]:
        db_id     = db["DBInstanceIdentifier"]
        db_engine = db.get("Engine", "unknown")

        if db.get("PubliclyAccessible", False):
            findings.append(_finding(
                severity    = "CRITICAL",
                rule        = "no_public_rds",
                resource_id = db_id,
                region      = region,
                detail      = f"RDS instance ({db_engine}) has PubliclyAccessible=True",
            ))

    return findings


# ── GOLDEN RULE 5: PUBLIC S3 BUCKETS ─────────────────────────────────────────
#
# Rule: No S3 bucket may have Block Public Access disabled.
# Why:  Public S3 buckets are one of the most common causes of data breaches.
#       AWS provides a dedicated "Block Public Access" setting per bucket —
#       we check that all four blocks are enabled.

def find_public_s3_buckets(region: str) -> list[dict]:
    """
    S3 is a global service but buckets are region-specific.
    We only scan buckets in the current region to avoid double-counting.
    Checks the Block Public Access settings — all four must be True.
    """
    findings = []

    # S3 bucket listing is always done against us-east-1 regardless of region.
    # We filter to the current region after listing.
    s3 = boto3.client("s3", region_name="us-east-1")

    try:
        all_buckets = s3.list_buckets().get("Buckets", [])
    except Exception:
        return findings

    for bucket in all_buckets:
        bucket_name = bucket["Name"]

        # Check which region this bucket lives in
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            # AWS returns None for us-east-1 — normalise it
            bucket_region = location["LocationConstraint"] or "us-east-1"
        except Exception:
            continue

        # Only check buckets that belong to the current region
        if bucket_region != region:
            continue

        # Now check the Block Public Access configuration
        try:
            bpa = s3.get_public_access_block(Bucket=bucket_name)
            config = bpa["PublicAccessBlockConfiguration"]

            # All four settings must be True for the bucket to be fully protected
            all_blocked = all([
                config.get("BlockPublicAcls",       False),
                config.get("IgnorePublicAcls",      False),
                config.get("BlockPublicPolicy",     False),
                config.get("RestrictPublicBuckets", False),
            ])

            if not all_blocked:
                # Find which specific settings are off — useful for remediation
                disabled = [
                    name for name, key in {
                        "BlockPublicAcls":       "BlockPublicAcls",
                        "IgnorePublicAcls":      "IgnorePublicAcls",
                        "BlockPublicPolicy":     "BlockPublicPolicy",
                        "RestrictPublicBuckets": "RestrictPublicBuckets",
                    }.items()
                    if not config.get(key, False)
                ]
                findings.append(_finding(
                    severity    = "CRITICAL",
                    rule        = "no_public_s3_buckets",
                    resource_id = bucket_name,
                    region      = region,
                    detail      = f"Block Public Access disabled: {', '.join(disabled)}",
                ))

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No Block Public Access config at all — bucket is open by default
            findings.append(_finding(
                severity    = "CRITICAL",
                rule        = "no_public_s3_buckets",
                resource_id = bucket_name,
                region      = region,
                detail      = "No Block Public Access configuration — bucket is open by default",
            ))
        except Exception:
            continue

    return findings


# ── GOLDEN RULE 4: ORPHANED ELASTIC IPs ──────────────────────────────────────
#
# Rule: Every Elastic IP must be attached to a running resource.
# Why:  Unattached EIPs cost money (~$4/month each) and accumulate silently.
#       They also represent unused public IP space that should be released.

# ── GOLDEN RULE 6: UNENCRYPTED S3 BUCKETS ────────────────────────────────────
#
# Rule: Every S3 bucket must have server-side encryption enabled.
# Why:  Encryption at rest protects data if AWS infrastructure is ever
#       compromised. It's free, one setting, and there's no excuse not to.

def find_unencrypted_s3_buckets(region: str) -> list[dict]:
    """
    Checks every bucket in this region for a default encryption configuration.
    AWS S3 now encrypts by default for new buckets (since Jan 2023), but older
    buckets may still have no encryption configured — we catch those.
    """
    findings = []
    s3 = boto3.client("s3", region_name="us-east-1")

    try:
        all_buckets = s3.list_buckets().get("Buckets", [])
    except Exception:
        return findings

    for bucket in all_buckets:
        bucket_name = bucket["Name"]

        # Filter to current region only
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = location["LocationConstraint"] or "us-east-1"
        except Exception:
            continue

        if bucket_region != region:
            continue

        # Check server-side encryption configuration
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc["ServerSideEncryptionConfiguration"].get("Rules", [])

            # Verify at least one rule exists and uses AES256 or aws:kms
            if not rules:
                raise Exception("No encryption rules")

            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
            if algo not in ("AES256", "aws:kms"):
                findings.append(_finding(
                    severity    = "WARNING",
                    rule        = "s3_encryption_enabled",
                    resource_id = bucket_name,
                    region      = region,
                    detail      = f"Bucket uses unknown encryption algorithm: {algo}",
                ))

        except s3.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_finding(
                    severity    = "WARNING",
                    rule        = "s3_encryption_enabled",
                    resource_id = bucket_name,
                    region      = region,
                    detail      = "No default encryption configured on bucket",
                ))
        except Exception:
            continue

    return findings


# ── GOLDEN RULE 7: UNENCRYPTED EBS VOLUMES ───────────────────────────────────
#
# Rule: All EBS volumes must be encrypted.
# Why:  Unencrypted EBS snapshots can be shared accidentally, exposing raw
#       disk data. Encryption at rest is free on modern instance types.

def find_unencrypted_ebs_volumes(region: str) -> list[dict]:
    """
    Scans all EBS volumes in the region and flags any where
    Encrypted = False. Includes the attached instance ID if available
    so the team knows exactly which server is affected.
    """
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    paginator = ec2.get_paginator("describe_volumes")

    for page in paginator.paginate():
        for volume in page["Volumes"]:
            if not volume.get("Encrypted", False):
                volume_id = volume["VolumeId"]
                state     = volume.get("State", "unknown")

                # Find attached instance if any
                attachments = volume.get("Attachments", [])
                instance_id = attachments[0]["InstanceId"] if attachments else "not attached"

                findings.append(_finding(
                    severity    = "WARNING",
                    rule        = "ebs_encryption_enabled",
                    resource_id = volume_id,
                    region      = region,
                    detail      = f"EBS volume is unencrypted (state: {state}, instance: {instance_id})",
                ))

    return findings


# ── GOLDEN RULE 8: EC2 IMDSv2 NOT ENFORCED ───────────────────────────────────
#
# Rule: All EC2 instances must enforce IMDSv2 (token-required mode).
# Why:  IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF) attacks.
#       An attacker exploiting an SSRF bug can steal IAM credentials from the
#       metadata service (169.254.169.254) using a simple HTTP request.
#       IMDSv2 requires a session token, blocking this attack entirely.

def find_imdsv1_instances(region: str) -> list[dict]:
    """
    Scans all running EC2 instances and flags any where the metadata
    service is set to 'optional' (IMDSv1 allowed) instead of 'required'.
    """
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    ):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]

                # Get the Name tag for better context in the alert
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", "unnamed")

                # MetadataOptions controls IMDSv1 vs IMDSv2
                metadata_opts = instance.get("MetadataOptions", {})
                http_tokens   = metadata_opts.get("HttpTokens", "optional")

                # "optional" = IMDSv1 allowed (vulnerable)
                # "required" = IMDSv2 enforced (secure)
                if http_tokens != "required":
                    findings.append(_finding(
                        severity    = "CRITICAL",
                        rule        = "ec2_imdsv2_required",
                        resource_id = instance_id,
                        region      = region,
                        detail      = f"Instance '{name}' allows IMDSv1 — vulnerable to SSRF credential theft",
                    ))

    return findings


def find_orphaned_eips(region: str) -> list[dict]:
    """
    Scans all Elastic IP addresses in the region and flags any that are
    allocated but not currently associated with any resource.
    """
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    # describe_addresses() returns all EIPs in the region.
    response = ec2.describe_addresses()

    for eip in response["Addresses"]:
        allocation_id = eip.get("AllocationId", eip.get("PublicIp", "unknown"))
        public_ip     = eip.get("PublicIp", "unknown")

        # If "AssociationId" is missing from the response, the EIP is unattached.
        if "AssociationId" not in eip:
            findings.append(_finding(
                severity    = "WARNING",
                rule        = "no_orphaned_eips",
                resource_id = allocation_id,
                region      = region,
                detail      = f"Elastic IP {public_ip} is allocated but not associated with any resource",
            ))

    return findings