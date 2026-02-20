"""
Network Auditor — cost_optimizer.py
=====================================
Identifies idle/wasted AWS resources and calculates exact monthly cost.

Same contract as checks.py:
    Input:  region (str), session (boto3.Session)
    Output: list of finding dicts

Each finding includes a `monthly_cost_usd` field so report.py
can total up the waste and show clients exactly what they're burning.

Resources checked:
  1. Idle Load Balancers  (0 requests + 0 healthy targets for 7 days)
  2. Idle NAT Gateways    (0 bytes out for 7 days)
  3. Unattached EBS       (available state, not mounted to any instance)
  4. Unused Elastic IPs   (already in checks.py — cost added here)
  5. Stopped EC2          (stopped but still paying for EBS + EIP)
"""

import boto3
import datetime


# ── PRICING CONSTANTS (USD/month) ─────────────────────────────────────────────
# Based on eu-west-1 on-demand pricing — adjust per region if needed

PRICES = {
    "alb_per_month":        18.00,   # ALB fixed hourly charge (~$0.025/hr)
    "nlb_per_month":        18.00,   # NLB fixed hourly charge (~$0.025/hr)
    "nat_gateway_per_month": 37.00,  # NAT GW fixed hourly charge (~$0.052/hr)
    "ebs_gp2_per_gb":        0.10,   # gp2 per GB/month
    "ebs_gp3_per_gb":        0.08,   # gp3 per GB/month
    "ebs_io1_per_gb":        0.125,  # io1 per GB/month
    "eip_unused_per_month":  3.65,   # $0.005/hr when not attached
}

CLOUDWATCH_LOOKBACK_DAYS = 7   # how far back to check for traffic


# ── SHARED HELPERS ─────────────────────────────────────────────────────────────

def _cost_finding(rule: str, resource_id: str, region: str,
                  detail: str, monthly_cost: float, account_id: str = None) -> dict:
    """
    Same shape as checks.py _finding() but with cost fields added.
    Severity is always COST_WASTE so report.py can handle it separately.
    """
    finding = {
        "severity":         "COST_WASTE",
        "rule":             rule,
        "resource_id":      resource_id,
        "region":           region,
        "detail":           detail,
        "monthly_cost_usd": round(monthly_cost, 2),
        "annual_cost_usd":  round(monthly_cost * 12, 2),
    }
    if account_id:
        finding["account_id"] = account_id
    return finding


def _client(service: str, region: str, session: boto3.Session = None):
    """Identical to checks.py — reuse same pattern."""
    if session:
        return session.client(service, region_name=region)
    return boto3.client(service, region_name=region)


def _get_metric_sum(cw, namespace: str, metric_name: str,
                    dimensions: list, days: int = 7) -> float:
    """
    Returns the SUM of a CloudWatch metric over the last N days.
    Returns 0.0 if no data — meaning the resource was completely idle.
    """
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=days)

    try:
        response = cw.get_metric_statistics(
            Namespace   = namespace,
            MetricName  = metric_name,
            Dimensions  = dimensions,
            StartTime   = start,
            EndTime     = end,
            Period      = days * 86400,  # one single data point over the whole window
            Statistics  = ["Sum"],
        )
        datapoints = response.get("Datapoints", [])
        if not datapoints:
            return 0.0
        return sum(dp["Sum"] for dp in datapoints)
    except Exception:
        return 0.0


# ── COST CHECK 1: IDLE LOAD BALANCERS ─────────────────────────────────────────

def find_idle_load_balancers(region: str, session: boto3.Session = None) -> list[dict]:
    """
    Flags ALBs and NLBs that have had zero requests AND zero healthy targets
    for the past 7 days. These are billing ~$18/month for nothing.
    """
    elb = _client("elbv2", region, session)
    cw  = _client("cloudwatch", region, session)
    findings = []

    try:
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                lb_arn   = lb["LoadBalancerArn"]
                lb_name  = lb["LoadBalancerName"]
                lb_type  = lb["Type"]          # application | network
                lb_state = lb["State"]["Code"] # active | provisioning | failed

                if lb_state != "active":
                    continue

                # Extract the short name for CloudWatch dimensions
                # ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
                lb_dim = "/".join(lb_arn.split("loadbalancer/")[-1].split("/"))

                # Check request count over last 7 days
                metric_name = "RequestCount" if lb_type == "application" else "ActiveFlowCount"
                request_sum = _get_metric_sum(
                    cw,
                    namespace   = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB",
                    metric_name = metric_name,
                    dimensions  = [{"Name": "LoadBalancer", "Value": lb_dim}],
                )

                # Check healthy host count
                healthy_hosts = _get_metric_sum(
                    cw,
                    namespace   = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB",
                    metric_name = "HealthyHostCount",
                    dimensions  = [{"Name": "LoadBalancer", "Value": lb_dim}],
                )

                is_idle = (request_sum == 0 and healthy_hosts == 0)

                if is_idle:
                    monthly_cost = PRICES["alb_per_month"] if lb_type == "application" else PRICES["nlb_per_month"]
                    findings.append(_cost_finding(
                        rule         = "idle_load_balancer",
                        resource_id  = lb_name,
                        region       = region,
                        detail       = (
                            f"{lb_type.upper()} '{lb_name}' has had 0 requests and "
                            f"0 healthy targets for {CLOUDWATCH_LOOKBACK_DAYS} days — "
                            f"ARN: {lb_arn}"
                        ),
                        monthly_cost = monthly_cost,
                    ))

    except Exception as e:
        print(f"      [WARN] find_idle_load_balancers failed in {region}: {e}")

    return findings


# ── COST CHECK 2: IDLE NAT GATEWAYS ───────────────────────────────────────────

def find_idle_nat_gateways(region: str, session: boto3.Session = None) -> list[dict]:
    """
    Flags NAT Gateways with zero bytes processed in the last 7 days.
    These cost ~$37/month fixed + $0.045/GB — idle ones are pure waste.
    """
    ec2 = _client("ec2", region, session)
    cw  = _client("cloudwatch", region, session)
    findings = []

    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ):
            for nat in page["NatGateways"]:
                nat_id    = nat["NatGatewayId"]
                subnet_id = nat.get("SubnetId", "unknown")
                vpc_id    = nat.get("VpcId", "unknown")

                bytes_out = _get_metric_sum(
                    cw,
                    namespace   = "AWS/NATGateway",
                    metric_name = "BytesOutToDestination",
                    dimensions  = [{"Name": "NatGatewayId", "Value": nat_id}],
                )

                bytes_in = _get_metric_sum(
                    cw,
                    namespace   = "AWS/NATGateway",
                    metric_name = "BytesInFromDestination",
                    dimensions  = [{"Name": "NatGatewayId", "Value": nat_id}],
                )

                if bytes_out == 0 and bytes_in == 0:
                    findings.append(_cost_finding(
                        rule         = "idle_nat_gateway",
                        resource_id  = nat_id,
                        region       = region,
                        detail       = (
                            f"NAT Gateway '{nat_id}' processed 0 bytes in {CLOUDWATCH_LOOKBACK_DAYS} days "
                            f"(VPC: {vpc_id}, Subnet: {subnet_id})"
                        ),
                        monthly_cost = PRICES["nat_gateway_per_month"],
                    ))

    except Exception as e:
        print(f"      [WARN] find_idle_nat_gateways failed in {region}: {e}")

    return findings


# ── COST CHECK 3: UNATTACHED EBS VOLUMES ──────────────────────────────────────

def find_unattached_ebs_volumes(region: str, session: boto3.Session = None) -> list[dict]:
    """
    Flags EBS volumes in 'available' state — created but never attached,
    or detached and forgotten. Billing continues regardless.
    """
    ec2 = _client("ec2", region, session)
    findings = []

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for vol in page["Volumes"]:
                vol_id   = vol["VolumeId"]
                vol_type = vol.get("VolumeType", "gp2")
                size_gb  = vol.get("Size", 0)
                tags     = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                name     = tags.get("Name", "unnamed")

                # Calculate cost based on volume type
                price_per_gb = PRICES.get(f"ebs_{vol_type}_per_gb", PRICES["ebs_gp2_per_gb"])
                monthly_cost = size_gb * price_per_gb

                # How long has it been sitting unattached?
                create_time = vol.get("CreateTime")
                if create_time:
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - create_time).days
                    age_str  = f"{age_days} days"
                else:
                    age_str = "unknown age"

                findings.append(_cost_finding(
                    rule         = "unattached_ebs_volume",
                    resource_id  = vol_id,
                    region       = region,
                    detail       = (
                        f"EBS volume '{name}' ({vol_type}, {size_gb}GB) unattached "
                        f"for {age_str} — not mounted to any instance"
                    ),
                    monthly_cost = monthly_cost,
                ))

    except Exception as e:
        print(f"      [WARN] find_unattached_ebs_volumes failed in {region}: {e}")

    return findings


# ── COST CHECK 4: STOPPED EC2 INSTANCES ───────────────────────────────────────

def find_stopped_ec2_instances(region: str, session: boto3.Session = None) -> list[dict]:
    """
    Flags EC2 instances in 'stopped' state.
    Stopped instances don't bill for compute, but still bill for:
      - Attached EBS volumes (calculated here)
      - Elastic IPs attached to them
    Long-stopped instances are usually forgotten and should be terminated.
    """
    ec2 = _client("ec2", region, session)
    findings = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id  = instance["InstanceId"]
                    instance_type = instance.get("InstanceType", "unknown")
                    tags         = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                    name         = tags.get("Name", "unnamed")

                    # Calculate EBS cost for all attached volumes
                    ebs_cost = 0.0
                    ebs_detail_parts = []
                    for mapping in instance.get("BlockDeviceMappings", []):
                        vol_id = mapping.get("Ebs", {}).get("VolumeId")
                        if not vol_id:
                            continue
                        try:
                            vol_resp = ec2.describe_volumes(VolumeIds=[vol_id])
                            for vol in vol_resp["Volumes"]:
                                vol_type   = vol.get("VolumeType", "gp2")
                                size_gb    = vol.get("Size", 0)
                                price_gb   = PRICES.get(f"ebs_{vol_type}_per_gb", PRICES["ebs_gp2_per_gb"])
                                vol_cost   = size_gb * price_gb
                                ebs_cost  += vol_cost
                                ebs_detail_parts.append(f"{vol_id}({size_gb}GB {vol_type})")
                        except Exception:
                            continue

                    # How long has it been stopped?
                    launch_time = instance.get("LaunchTime")
                    if launch_time:
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - launch_time).days
                        age_str  = f"launched {age_days} days ago"
                    else:
                        age_str = "unknown age"

                    ebs_summary = ", ".join(ebs_detail_parts) if ebs_detail_parts else "no volumes"

                    findings.append(_cost_finding(
                        rule         = "stopped_ec2_instance",
                        resource_id  = instance_id,
                        region       = region,
                        detail       = (
                            f"EC2 '{name}' ({instance_type}) is stopped but still billing for EBS — "
                            f"{ebs_summary} | {age_str}"
                        ),
                        monthly_cost = ebs_cost,
                    ))

    except Exception as e:
        print(f"      [WARN] find_stopped_ec2_instances failed in {region}: {e}")

    return findings


# ── ALL COST CHECKS ───────────────────────────────────────────────────────────
# This list is imported by main.py — same pattern as GOLDEN_RULES

COST_CHECKS = [
    find_idle_load_balancers,
    find_idle_nat_gateways,
    find_unattached_ebs_volumes,
    find_stopped_ec2_instances,
]