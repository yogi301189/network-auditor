"""
Network Auditor — main.py
=========================
Multi-account entry point. Scans every account in accounts.json
by either using direct credentials (home account) or assuming
a cross-account role via STS (target accounts).

Every finding is tagged with account_id and account_name so the
report clearly shows which account each violation came from.
"""

import json
import boto3
from pathlib import Path
from auditor import checks, report, pdf_report


# ── CONFIGURATION ─────────────────────────────────────────────────────────────

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

ACCOUNTS_FILE = Path(__file__).parent.parent / "accounts.json"


# ── ACCOUNT LOADER ────────────────────────────────────────────────────────────

def load_accounts() -> list[dict]:
    with open(ACCOUNTS_FILE) as f:
        accounts = json.load(f)
    print(f"[INFO] Loaded {len(accounts)} account(s) from accounts.json")
    return accounts


# ── CREDENTIAL MANAGER ────────────────────────────────────────────────────────

def get_session_for_account(account: dict) -> boto3.Session:
    """
    Returns a boto3 Session for the given account.
    If role_arn is null  → use default credentials (home account)
    If role_arn is set   → assume the cross-account role via STS
    """
    role_arn = account.get("role_arn")

    if not role_arn:
        print(f"  [AUTH] Using direct credentials for {account['account_name']}")
        return boto3.Session()

    print(f"  [AUTH] Assuming role: {role_arn}")
    sts = boto3.client("sts")

    try:
        response = sts.assume_role(
            RoleArn         = role_arn,
            RoleSessionName = f"NetworkAuditor-{account['account_id']}",
            DurationSeconds = 3600,
        )
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id     = creds["AccessKeyId"],
            aws_secret_access_key = creds["SecretAccessKey"],
            aws_session_token     = creds["SessionToken"],
        )

    except Exception as e:
        print(f"  [ERROR] Failed to assume role for {account['account_name']}: {e}")
        return None


# ── REGION DISCOVERY ──────────────────────────────────────────────────────────

def get_active_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return sorted(r["RegionName"] for r in response["Regions"])


# ── ACCOUNT SCANNER ───────────────────────────────────────────────────────────

def scan_account(account: dict, session: boto3.Session) -> list[dict]:
    """
    Runs all Golden Rules against all regions for a single account.
    Tags every finding with account_id and account_name.
    """
    account_findings = []
    account_id   = account["account_id"]
    account_name = account["account_name"]

    print(f"\n{'='*60}")
    print(f"  SCANNING: {account_name} ({account_id})")
    print(f"{'='*60}")

    regions = get_active_regions(session)
    print(f"  [INFO] Found {len(regions)} active regions")

    for region in regions:
        print(f"\n  [REGION] {region}")

        for rule_function in GOLDEN_RULES:
            rule_name = rule_function.__name__
            print(f"    → Running: {rule_name}")

            try:
                findings = rule_function(region, session=session)

                for finding in findings:
                    finding["account_id"]   = account_id
                    finding["account_name"] = account_name

                account_findings.extend(findings)

                if findings:
                    print(f"      ⚠  {len(findings)} violation(s) found")
                else:
                    print(f"      ✓  Clean")

            except Exception as e:
                print(f"      [ERROR] {rule_name} failed in {region}: {e}")

    return account_findings


# ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────────

def run_audit() -> list[dict]:
    all_findings = []
    accounts     = load_accounts()

    for account in accounts:
        session = get_session_for_account(account)

        if session is None:
            print(f"  [SKIP] Could not get session for {account['account_name']} — skipping")
            continue

        findings = scan_account(account, session)
        all_findings.extend(findings)
        print(f"\n  [DONE] {account['account_name']} — {len(findings)} violation(s) found")

    return all_findings


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Network Auditor — Multi-Account Scan")
    print("  Mode: READ-ONLY (no changes will be made)")
    print("=" * 60)

    findings = run_audit()

    print(f"\n[COMPLETE] Total violations across all accounts: {len(findings)}")
    report.generate(findings)
    latest_json = sorted(Path("reports").glob("findings_*.json"))[-1]
    pdf_report.generate_pdf(str(latest_json))