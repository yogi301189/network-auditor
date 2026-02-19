"""
tag_default_vpcs.py
====================
One-shot script to apply the required tags to every default VPC
across all active AWS regions.

Run from the network-auditor/ folder:
    python tag_default_vpcs.py

It will show you exactly what it's going to tag before doing anything,
then ask for confirmation. Safe to run multiple times — re-tagging
an already-tagged VPC just overwrites with the same values.
"""

import boto3

# ── CONFIGURE YOUR TAGS HERE ─────────────────────────────────────────────────
# Edit these four values to match your details before running.

TAGS = [
    {"Key": "Owner",       "Value": "yogifst@gmail.com"},   # ← your email
    {"Key": "Environment", "Value": "sandbox"},
    {"Key": "CostCenter",  "Value": "personal"},
    {"Key": "Project",     "Value": "netdevops-lab"},
]

# ── SCRIPT ────────────────────────────────────────────────────────────────────

def get_active_regions() -> list[str]:
    ec2 = boto3.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return sorted(r["RegionName"] for r in response["Regions"])


def find_default_vpcs() -> list[dict]:
    """Returns a list of {region, vpc_id} for every default VPC found."""
    results = []
    regions = get_active_regions()

    print(f"Scanning {len(regions)} regions for default VPCs...\n")

    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)
        response = ec2.describe_vpcs(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        )
        for vpc in response["Vpcs"]:
            results.append({"region": region, "vpc_id": vpc["VpcId"]})

    return results


def tag_vpcs(default_vpcs: list[dict]) -> None:
    """Applies TAGS to every VPC in the list."""
    for item in default_vpcs:
        region = item["region"]
        vpc_id = item["vpc_id"]

        ec2 = boto3.client("ec2", region_name=region)
        ec2.create_tags(Resources=[vpc_id], Tags=TAGS)
        print(f"  ✅ Tagged {vpc_id} ({region})")


def main():
    default_vpcs = find_default_vpcs()

    if not default_vpcs:
        print("No default VPCs found — nothing to tag.")
        return

    # Show the plan before doing anything
    print(f"Found {len(default_vpcs)} default VPC(s) to tag:\n")
    for item in default_vpcs:
        print(f"  • {item['vpc_id']} ({item['region']})")

    print(f"\nTags to apply:")
    for tag in TAGS:
        print(f"  • {tag['Key']}: {tag['Value']}")

    # Ask for confirmation
    print()
    confirm = input("Proceed? (yes/no): ").strip().lower()

    if confirm != "yes":
        print("Aborted — no changes made.")
        return

    print("\nTagging VPCs...")
    tag_vpcs(default_vpcs)
    print(f"\nDone — {len(default_vpcs)} VPC(s) tagged.")
    print("Run the auditor again to confirm all warnings are cleared.")


if __name__ == "__main__":
    main()