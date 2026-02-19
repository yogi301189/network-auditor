"""
Network Auditor — report.py
============================
Takes the raw findings list from main.py and produces two outputs:

  1. findings.json  — machine-readable, every finding in full detail
  2. summary.md     — human-readable, designed for Slack or email

This file knows nothing about AWS. It only knows how to format data.
That separation means you can test it without any AWS credentials.
"""

import json
import datetime
from pathlib import Path


# ── CONFIGURATION ─────────────────────────────────────────────────────────────

OUTPUT_DIR = Path("reports")   # folder where output files are saved

# Emoji used in the Markdown summary — change these to match your team's taste
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "WARNING":  "🟡",
}

# Rules in this set are shown first in the summary, regardless of region order
RULE_PRIORITY = ["no_open_ssh_rdp", "no_public_rds"]


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _group_by_severity(findings: list[dict]) -> dict:
    """
    Splits the flat findings list into a dict keyed by severity.
    Input:  [{"severity": "CRITICAL", ...}, {"severity": "WARNING", ...}]
    Output: {"CRITICAL": [...], "WARNING": [...]}
    """
    grouped = {"CRITICAL": [], "WARNING": []}
    for f in findings:
        severity = f.get("severity", "WARNING")
        grouped.setdefault(severity, []).append(f)
    return grouped


def _sort_findings(findings: list[dict]) -> list[dict]:
    """
    Sorts findings so CRITICAL comes before WARNING,
    and high-priority rules appear first within each severity group.
    """
    def sort_key(f):
        severity_order = 0 if f["severity"] == "CRITICAL" else 1
        rule_order = RULE_PRIORITY.index(f["rule"]) if f["rule"] in RULE_PRIORITY else 99
        return (severity_order, rule_order, f["region"])

    return sorted(findings, key=sort_key)


# ── JSON REPORT ───────────────────────────────────────────────────────────────

def _write_json(findings: list[dict], timestamp: str) -> Path:
    """
    Writes the full findings list to a JSON file.
    Includes a metadata header so the file is self-describing.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / f"findings_{timestamp}.json"

    output = {
        "metadata": {
            "generated_at": timestamp,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "warning_count":  sum(1 for f in findings if f["severity"] == "WARNING"),
        },
        "findings": _sort_findings(findings),
    }

    with open(filepath, "w") as fh:
        json.dump(output, fh, indent=2)

    print(f"[REPORT] JSON written → {filepath}")
    return filepath


# ── MARKDOWN SUMMARY ──────────────────────────────────────────────────────────

def _write_markdown(findings: list[dict], timestamp: str) -> Path:
    """
    Writes a human-readable Markdown summary.
    Designed to paste cleanly into Slack, GitHub issues, or email.

    Structure:
      - Header with scan time and overall health status
      - CRITICAL section (if any)
      - WARNING section (if any)
      - Clean bill of health message (if zero findings)
    """
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / f"summary_{timestamp}.md"

    grouped  = _group_by_severity(findings)
    critical = grouped["CRITICAL"]
    warnings = grouped["WARNING"]

    lines = []

    # ── Header ──
    lines.append("# 🔍 Network Auditor Report")
    lines.append(f"**Scan time:** {timestamp.replace('_', ' ')}  ")
    lines.append(f"**Total violations:** {len(findings)}  ")

    if critical:
        lines.append(f"**Status:** 🔴 ACTION REQUIRED — {len(critical)} critical violation(s) found")
    elif warnings:
        lines.append(f"**Status:** 🟡 {len(warnings)} warning(s) — review when possible")
    else:
        lines.append("**Status:** ✅ All checks passed — network is clean")

    lines.append("")  # blank line
    lines.append("---")
    lines.append("")

    # ── Critical section ──
    if critical:
        lines.append("## 🔴 Critical Violations")
        lines.append("*These require immediate attention.*")
        lines.append("")
        for f in _sort_findings(critical):
            account = f.get("account_name", "")
            account_str = f" | {account}" if account else ""
            lines.append(f"**{f['rule']}** — `{f['resource_id']}` ({f['region']}{account_str})")
            lines.append(f"> {f['detail']}")
            lines.append("")

    # ── Warning section ──
    if warnings:
        lines.append("## 🟡 Warnings")
        lines.append("*Hygiene and cost issues — not urgent, but track them.*")
        lines.append("")
        for f in _sort_findings(warnings):
            account = f.get("account_name", "")
            account_str = f" | {account}" if account else ""
            lines.append(f"**{f['rule']}** — `{f['resource_id']}` ({f['region']}{account_str})")
            lines.append(f"> {f['detail']}")
            lines.append("")

    # ── All clear ──
    if not findings:
        lines.append("## ✅ All Golden Rules Passed")
        lines.append("No violations found across all scanned regions.")
        lines.append("")
        lines.append("*Keep it up — the network is clean.*")

    # ── Footer ──
    lines.append("")
    lines.append("---")
    lines.append("*Generated by Network Auditor — read-only scan, no changes made.*")

    with open(filepath, "w") as fh:
        fh.write("\n".join(lines))

    print(f"[REPORT] Markdown written → {filepath}")
    return filepath


# ── PUBLIC INTERFACE ──────────────────────────────────────────────────────────

def generate(findings: list[dict]) -> dict:
    """
    The only function main.py calls.
    Produces both output files and prints a terminal summary.
    Returns a dict of the file paths, useful for testing or piping to Slack.
    """
    # Use a sortable timestamp format: 2026-02-18_06-00-00
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    json_path = _write_json(findings, timestamp)
    md_path   = _write_markdown(findings, timestamp)

    # ── Terminal summary (always printed, regardless of findings) ──
    grouped  = _group_by_severity(findings)
    critical = grouped["CRITICAL"]
    warnings = grouped["WARNING"]

    print("\n" + "=" * 60)
    print("  AUDIT SUMMARY")
    print("=" * 60)
    print(f"  🔴 Critical : {len(critical)}")
    print(f"  🟡 Warnings : {len(warnings)}")
    print(f"  Total      : {len(findings)}")
    print("=" * 60)

    if critical:
        print("\n  Critical violations requiring immediate action:")
        for f in critical:
            print(f"  • [{f['region']}] {f['resource_id']} — {f['detail']}")

    print(f"\n  Full report: {json_path}")
    print(f"  Summary:     {md_path}\n")

    return {"json": str(json_path), "markdown": str(md_path)}