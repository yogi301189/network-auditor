"""
Network Auditor — cost_report.py
==================================
Formats cost optimizer findings into JSON + Markdown reports
and sends a Slack alert with the waste summary.

Follows the exact same pattern as report.py — same file naming,
same OUTPUT_DIR, same generate() interface so main.py can call it
identically.

The key difference: findings have a `monthly_cost_usd` field
so we can total up the waste and show annual projections.
"""

import json
import os
import datetime
import urllib.request
from pathlib import Path


# ── CONFIGURATION ─────────────────────────────────────────────────────────────

OUTPUT_DIR = Path("reports")

RULE_LABELS = {
    "idle_load_balancer":    "Idle Load Balancer",
    "idle_nat_gateway":      "Idle NAT Gateway",
    "unattached_ebs_volume": "Unattached EBS Volume",
    "stopped_ec2_instance":  "Stopped EC2 Instance (EBS billing)",
}


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _group_by_rule(findings: list[dict]) -> dict:
    grouped = {}
    for f in findings:
        rule = f.get("rule", "unknown")
        grouped.setdefault(rule, []).append(f)
    return grouped


def _total_cost(findings: list[dict]) -> float:
    return sum(f.get("monthly_cost_usd", 0.0) for f in findings)


# ── JSON REPORT ───────────────────────────────────────────────────────────────

def _write_json(findings: list[dict], timestamp: str) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / f"cost_waste_{timestamp}.json"

    total_monthly = _total_cost(findings)

    output = {
        "metadata": {
            "generated_at":       timestamp,
            "total_findings":     len(findings),
            "total_monthly_usd":  round(total_monthly, 2),
            "total_annual_usd":   round(total_monthly * 12, 2),
        },
        "findings": sorted(findings, key=lambda f: f.get("monthly_cost_usd", 0), reverse=True),
    }

    with open(filepath, "w") as fh:
        json.dump(output, fh, indent=2)

    print(f"[COST REPORT] JSON written → {filepath}")
    return filepath


# ── MARKDOWN REPORT ───────────────────────────────────────────────────────────

def _write_markdown(findings: list[dict], timestamp: str) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / f"cost_waste_{timestamp}.md"

    total_monthly = _total_cost(findings)
    total_annual  = total_monthly * 12
    grouped       = _group_by_rule(findings)

    lines = []

    # ── Header ──
    lines.append("# 💸 Cost Waste Report")
    lines.append(f"**Scan time:** {timestamp.replace('_', ' ')}  ")
    lines.append(f"**Idle resources found:** {len(findings)}  ")
    lines.append(f"**Total waste:** ${total_monthly:,.2f}/month — ${total_annual:,.2f}/year  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not findings:
        lines.append("## ✅ No idle resources found")
        lines.append("All Load Balancers, NAT Gateways, EBS volumes and EC2 instances are active.")
    else:
        # ── Per-rule sections ──
        for rule, rule_findings in grouped.items():
            label        = RULE_LABELS.get(rule, rule)
            rule_total   = _total_cost(rule_findings)
            rule_annual  = rule_total * 12

            lines.append(f"## {label}s ({len(rule_findings)} found)")
            lines.append(f"**Cost: ${rule_total:,.2f}/month — ${rule_annual:,.2f}/year**")
            lines.append("")

            # Sort by cost descending within each rule
            for f in sorted(rule_findings, key=lambda x: x.get("monthly_cost_usd", 0), reverse=True):
                account = f.get("account_name", "")
                account_str = f" | {account}" if account else ""
                lines.append(f"- `{f['resource_id']}` ({f['region']}{account_str}) — **${f['monthly_cost_usd']:,.2f}/month**")
                lines.append(f"  > {f['detail']}")
                lines.append("")

        # ── Total summary ──
        lines.append("---")
        lines.append("")
        lines.append("## 💰 Total Waste Summary")
        lines.append("")
        lines.append("| Resource Type | Count | Monthly Cost | Annual Cost |")
        lines.append("|---|---|---|---|")
        for rule, rule_findings in grouped.items():
            label = RULE_LABELS.get(rule, rule)
            rc    = _total_cost(rule_findings)
            lines.append(f"| {label} | {len(rule_findings)} | ${rc:,.2f} | ${rc*12:,.2f} |")
        lines.append(f"| **TOTAL** | **{len(findings)}** | **${total_monthly:,.2f}** | **${total_annual:,.2f}** |")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by Network Auditor Cost Optimizer — read-only scan, no changes made.*")

    with open(filepath, "w") as fh:
        fh.write("\n".join(lines))

    print(f"[COST REPORT] Markdown written → {filepath}")
    return filepath


# ── SLACK ALERT ───────────────────────────────────────────────────────────────

def _send_slack_alert(findings: list[dict], timestamp: str):
    """
    Posts a cost waste summary to Slack.
    Reads SLACK_WEBHOOK_URL from environment — same as handler.py.
    Silently skips if the env var is not set (e.g. local dev runs).
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[COST REPORT] SLACK_WEBHOOK_URL not set — skipping Slack alert")
        return

    total_monthly = _total_cost(findings)
    total_annual  = total_monthly * 12
    grouped       = _group_by_rule(findings)

    if not findings:
        color = "#36a64f"
        header = "✅ Cost Optimizer — No idle resources found"
        summary_text = "All resources are active. No waste detected."
    else:
        color = "#ff9900"
        header = f"💸 Cost Optimizer — ${total_monthly:,.2f}/month wasted"
        summary_text = f"*{len(findings)} idle resources* found burning ${total_annual:,.2f}/year"

    # Build per-rule breakdown fields
    fields = []
    for rule, rule_findings in grouped.items():
        label      = RULE_LABELS.get(rule, rule)
        rule_total = _total_cost(rule_findings)
        fields.append({
            "type": "mrkdwn",
            "text": f"*{label}s ({len(rule_findings)}):*\n${rule_total:,.2f}/month"
        })

    # Top 3 biggest waste items
    top3 = sorted(findings, key=lambda f: f.get("monthly_cost_usd", 0), reverse=True)[:3]
    top3_lines = "\n".join(
        f"• `{f['resource_id']}` ({f['region']}) — ${f['monthly_cost_usd']:,.2f}/mo"
        for f in top3
    )

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": header}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": summary_text}
                },
                *(
                    [{
                        "type": "section",
                        "fields": fields
                    }] if fields else []
                ),
                *(
                    [{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Biggest waste items:*\n{top3_lines}"
                        }
                    }] if top3_lines else []
                ),
                {
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"💸 Network Auditor Cost Optimizer | {timestamp}"
                    }]
                }
            ]
        }]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            webhook_url,
            data    = data,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[COST REPORT] Slack alert sent — status {resp.status}")
    except Exception as e:
        print(f"[COST REPORT] Slack alert failed: {e}")


# ── TERMINAL SUMMARY ──────────────────────────────────────────────────────────

def _print_summary(findings: list[dict]):
    grouped       = _group_by_rule(findings)
    total_monthly = _total_cost(findings)
    total_annual  = total_monthly * 12

    print("\n" + "=" * 60)
    print("  COST WASTE SUMMARY")
    print("=" * 60)

    if not findings:
        print("  ✅ No idle resources found — nothing being wasted")
    else:
        for rule, rule_findings in grouped.items():
            label = RULE_LABELS.get(rule, rule)
            rc    = _total_cost(rule_findings)
            print(f"  💸 {label:<30} {len(rule_findings):>3} found   ${rc:>8,.2f}/month")

        print("  " + "-" * 56)
        print(f"  {'TOTAL WASTE':<30} {len(findings):>3} items   ${total_monthly:>8,.2f}/month")
        print(f"  {'ANNUAL PROJECTION':<42}   ${total_annual:>8,.2f}/year")

        print("\n  Top waste items:")
        top5 = sorted(findings, key=lambda f: f.get("monthly_cost_usd", 0), reverse=True)[:5]
        for f in top5:
            print(f"  • [{f['region']}] {f['resource_id']:<30} ${f['monthly_cost_usd']:>8,.2f}/month")

    print("=" * 60)


# ── PUBLIC INTERFACE ──────────────────────────────────────────────────────────

def generate(findings: list[dict]) -> dict:
    """
    The only function main.py calls.
    Same signature as report.generate() — drop-in compatible.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    json_path = _write_json(findings, timestamp)
    md_path   = _write_markdown(findings, timestamp)

    _print_summary(findings)
    _send_slack_alert(findings, timestamp)

    return {"json": str(json_path), "markdown": str(md_path)}