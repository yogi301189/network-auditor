"""
Network Auditor — main.py
=========================
The entry point. This file does three things only:
  1. Gets the list of AWS regions to scan
  2. Runs every Golden Rule check across every region
  3. Passes the findings to the reporter

It contains NO business logic. All rules live in checks.py.
All formatting lives in report.py. This file just coordinates.
"""

import boto3
from auditor import checks, report


# ── CONFIGURATION ────────────────────────────────────────────────────────────

# These are the rules we enforce. Each entry is a function from checks.py.
# To add a new rule later, write the function in checks.py and add it here.
GOLDEN_RULES = [
    checks.find_untagged_vpcs,
    checks.find_open_ssh_rdp,
    checks.find_public_rds,
    checks.find_orphaned_eips,
    checks.find_public_s3_buckets,
    checks.find_unencrypted_s3_buckets,
    checks.find_unencrypted_ebs_volumes,
    checks.find_imdsv1_instances,
]


# ── HELPERS ──────────────────────────────────────────────────────────────────

def get_active_regions() -> list[str]:
    """
    Returns all regions that are enabled in this AWS account.
    We use ec2.describe_regions() — a read-only API call.
    """
    ec2 = boto3.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    regions = [r["RegionName"] for r in response["Regions"]]
    print(f"[INFO] Found {len(regions)} active regions to scan.")
    return sorted(regions)


# ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────────

def run_audit() -> list[dict]:
    """
    The core loop. For every region, runs every Golden Rule check.
    Returns a flat list of all findings across all regions and rules.
    """
    all_findings = []
    regions = get_active_regions()

    for region in regions:
        print(f"\n[SCANNING] {region}")

        for rule_function in GOLDEN_RULES:
            rule_name = rule_function.__name__  # e.g. "find_open_ssh_rdp"
            print(f"  → Running: {rule_name}")

            try:
                # Each check function takes a region and returns a list of findings.
                # An empty list means: no violations found. That's the happy path.
                findings = rule_function(region)
                all_findings.extend(findings)

                if findings:
                    print(f"    ⚠  {len(findings)} violation(s) found")
                else:
                    print(f"    ✓  Clean")

            except Exception as e:
                # If one check fails (e.g. a service isn't available in that region),
                # we log it but don't stop the entire scan.
                print(f"    [ERROR] {rule_name} failed in {region}: {e}")

    return all_findings


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Network Auditor — Starting Scan")
    print("  Mode: READ-ONLY (no changes will be made)")
    print("=" * 60)

    # Step 1: Run all checks, collect findings
    findings = run_audit()

    # Step 2: Print a summary to the terminal
    print(f"\n[COMPLETE] Scan finished. Total violations found: {len(findings)}")

    # Step 3: Generate the report (JSON + Markdown)
    report.generate(findings)