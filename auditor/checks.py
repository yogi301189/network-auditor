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


# ── GOLDEN RULE 4: ORPHANED ELASTIC IPs ──────────────────────────────────────
#
# Rule: Every Elastic IP must be attached to a running resource.
# Why:  Unattached EIPs cost money (~$4/month each) and accumulate silently.
#       They also represent unused public IP space that should be released.

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