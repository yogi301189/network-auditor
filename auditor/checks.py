"""
Network Auditor — checks.py
============================
One function per Golden Rule. Every function follows the same contract:

    Input:  region (str), session (boto3.Session)
    Output: list of finding dicts

The session parameter is key for multi-account scanning —
it carries the correct credentials for each target account.
If no session is passed, boto3 uses default credentials (home account).
"""

import boto3


# ── SHARED HELPER ─────────────────────────────────────────────────────────────

def _finding(severity: str, rule: str, resource_id: str, region: str, detail: str) -> dict:
    return {
        "severity":    severity,
        "rule":        rule,
        "resource_id": resource_id,
        "region":      region,
        "detail":      detail,
    }

def _client(service: str, region: str, session: boto3.Session = None):
    """
    Returns a boto3 client using the provided session.
    If no session — falls back to default credentials (home account).
    This is the single change that enables multi-account scanning.
    """
    if session:
        return session.client(service, region_name=region)
    return boto3.client(service, region_name=region)


# ── GOLDEN RULE 1: UNTAGGED VPCs ─────────────────────────────────────────────

REQUIRED_TAGS = {"Owner", "Environment", "CostCenter", "Project"}

def find_untagged_vpcs(region: str, session: boto3.Session = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    findings = []

    response = ec2.describe_vpcs()
    for vpc in response["Vpcs"]:
        vpc_id = vpc["VpcId"]
        existing_tags = {tag["Key"] for tag in vpc.get("Tags", [])}
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

DANGEROUS_PORTS = {22, 3389}

def find_open_ssh_rdp(region: str, session: boto3.Session = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    findings = []

    response = ec2.describe_security_groups()
    for sg in response["SecurityGroups"]:
        sg_id   = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port   = rule.get("ToPort",   -1)

            exposed_ports = [p for p in DANGEROUS_PORTS if from_port <= p <= to_port]
            if not exposed_ports:
                continue

            ipv4_open = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            ipv6_open = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))

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


# ── GOLDEN RULE 3: PUBLIC RDS ─────────────────────────────────────────────────

def find_public_rds(region: str, session: boto3.Session = None) -> list[dict]:
    findings = []
    try:
        rds = _client("rds", region, session)
        response = rds.describe_db_instances()
        for db in response["DBInstances"]:
            if db.get("PubliclyAccessible", False):
                findings.append(_finding(
                    severity    = "CRITICAL",
                    rule        = "no_public_rds",
                    resource_id = db["DBInstanceIdentifier"],
                    region      = region,
                    detail      = f"RDS instance ({db.get('Engine', 'unknown')}) has PubliclyAccessible=True",
                ))
    except Exception:
        pass
    return findings


# ── GOLDEN RULE 4: ORPHANED ELASTIC IPs ──────────────────────────────────────

def find_orphaned_eips(region: str, session: boto3.Session = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    findings = []

    response = ec2.describe_addresses()
    for eip in response["Addresses"]:
        if "AssociationId" not in eip:
            findings.append(_finding(
                severity    = "WARNING",
                rule        = "no_orphaned_eips",
                resource_id = eip.get("AllocationId", eip.get("PublicIp", "unknown")),
                region      = region,
                detail      = f"Elastic IP {eip.get('PublicIp', 'unknown')} is not associated with any resource",
            ))
    return findings


# ── GOLDEN RULE 5: PUBLIC S3 BUCKETS ─────────────────────────────────────────

def find_public_s3_buckets(region: str, session: boto3.Session = None) -> list[dict]:
    findings = []
    s3 = _client("s3", "us-east-1", session)

    try:
        all_buckets = s3.list_buckets().get("Buckets", [])
    except Exception:
        return findings

    for bucket in all_buckets:
        bucket_name = bucket["Name"]
        try:
            location    = s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = location["LocationConstraint"] or "us-east-1"
        except Exception:
            continue

        if bucket_region != region:
            continue

        try:
            bpa    = s3.get_public_access_block(Bucket=bucket_name)
            config = bpa["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls",       False),
                config.get("IgnorePublicAcls",      False),
                config.get("BlockPublicPolicy",     False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                disabled = [k for k, v in config.items() if not v]
                findings.append(_finding(
                    severity    = "CRITICAL",
                    rule        = "no_public_s3_buckets",
                    resource_id = bucket_name,
                    region      = region,
                    detail      = f"Block Public Access disabled: {', '.join(disabled)}",
                ))
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
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


# ── GOLDEN RULE 6: UNENCRYPTED S3 BUCKETS ────────────────────────────────────

def find_unencrypted_s3_buckets(region: str, session: boto3.Session = None) -> list[dict]:
    findings = []
    s3 = _client("s3", "us-east-1", session)

    try:
        all_buckets = s3.list_buckets().get("Buckets", [])
    except Exception:
        return findings

    for bucket in all_buckets:
        bucket_name = bucket["Name"]
        try:
            location      = s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = location["LocationConstraint"] or "us-east-1"
        except Exception:
            continue

        if bucket_region != region:
            continue

        try:
            enc   = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc["ServerSideEncryptionConfiguration"].get("Rules", [])
            algo  = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "") if rules else ""
            if algo not in ("AES256", "aws:kms"):
                findings.append(_finding(
                    severity    = "WARNING",
                    rule        = "s3_encryption_enabled",
                    resource_id = bucket_name,
                    region      = region,
                    detail      = f"Bucket uses unknown encryption: {algo}",
                ))
        except s3.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
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

def find_unencrypted_ebs_volumes(region: str, session: boto3.Session = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    findings = []

    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for volume in page["Volumes"]:
            if not volume.get("Encrypted", False):
                attachments = volume.get("Attachments", [])
                instance_id = attachments[0]["InstanceId"] if attachments else "not attached"
                findings.append(_finding(
                    severity    = "WARNING",
                    rule        = "ebs_encryption_enabled",
                    resource_id = volume["VolumeId"],
                    region      = region,
                    detail      = f"EBS volume unencrypted (state: {volume.get('State','unknown')}, instance: {instance_id})",
                ))
    return findings


# ── GOLDEN RULE 8: EC2 IMDSv2 NOT ENFORCED ───────────────────────────────────

def find_imdsv1_instances(region: str, session: boto3.Session = None) -> list[dict]:
    ec2 = _client("ec2", region, session)
    findings = []

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    ):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id  = instance["InstanceId"]
                tags         = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name         = tags.get("Name", "unnamed")
                http_tokens  = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")

                if http_tokens != "required":
                    findings.append(_finding(
                        severity    = "CRITICAL",
                        rule        = "ec2_imdsv2_required",
                        resource_id = instance_id,
                        region      = region,
                        detail      = f"Instance '{name}' allows IMDSv1 — vulnerable to SSRF credential theft",
                    ))
    return findings