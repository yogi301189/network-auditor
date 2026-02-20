"""
Network Auditor — generate_dashboard.py
========================================
Reads the latest findings_*.json and cost_waste_*.json from reports/
and produces a fully data-driven executive_dashboard.html.

Run manually:
    python generate_dashboard.py

Or called from main.py after report.generate() and cost_report.generate().

Output: reports/executive_dashboard.html
"""

import json
import re
from pathlib import Path
from datetime import datetime, timezone

# ── PATHS ─────────────────────────────────────────────────────────────────────

REPORTS_DIR  = Path("reports")
OUTPUT_FILE  = REPORTS_DIR / "executive_dashboard.html"


# ── LOAD LATEST REPORTS ───────────────────────────────────────────────────────

def load_latest_json(pattern: str) -> dict:
    files = sorted(REPORTS_DIR.glob(pattern))
    if not files:
        return {"metadata": {}, "findings": []}
    with open(files[-1]) as f:
        return json.load(f)


# ── DATA HELPERS ──────────────────────────────────────────────────────────────

def group_by(items: list, key: str) -> dict:
    result = {}
    for item in items:
        k = item.get(key, "unknown")
        result.setdefault(k, []).append(item)
    return result


def total_cost(findings: list) -> float:
    return sum(f.get("monthly_cost_usd", 0.0) for f in findings)


RULE_LABELS = {
    "idle_load_balancer":    "Idle Load Balancer",
    "idle_nat_gateway":      "Idle NAT Gateway",
    "unattached_ebs_volume": "Unattached EBS Volume",
    "stopped_ec2_instance":  "Stopped EC2 Instance",
}

RULE_DISPLAY = {
    "no_open_ssh_rdp":           "No open SSH/RDP",
    "required_vpc_tags":         "Required VPC tags",
    "no_public_rds":             "No public RDS",
    "no_orphaned_eips":          "No orphaned EIPs",
    "no_public_s3_buckets":      "No public S3",
    "s3_encryption_enabled":     "S3 encryption",
    "ebs_encryption_enabled":    "EBS encryption",
    "ec2_imdsv2_required":       "EC2 IMDSv2",
}

ALL_GOLDEN_RULES = list(RULE_DISPLAY.keys())


# ── HTML BUILDERS ──────────────────────────────────────────────────────────────

def esc(s: str) -> str:
    """Escape HTML special characters."""
    return (str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;"))


def build_finding_rows(findings: list, limit: int = 20) -> str:
    if not findings:
        return '<div style="padding:24px;color:var(--muted);font-size:13px;">✅ No critical violations found.</div>'

    html = ""
    for f in findings[:limit]:
        sev   = f.get("severity", "WARNING").lower()
        dot   = "critical" if sev == "critical" else "warning"
        acct  = f.get("account_name", "")
        acct_str = f" · {esc(acct)}" if acct else ""
        html += f"""
        <div class="finding-row">
          <div class="sev-dot {dot}"></div>
          <div class="finding-info">
            <div class="finding-rule">{esc(f.get('rule',''))}</div>
            <div class="finding-resource">{esc(f.get('resource_id',''))}</div>
            <div class="finding-detail">{esc(f.get('detail',''))}{acct_str}</div>
          </div>
          <div class="finding-meta">
            <span class="region-tag">{esc(f.get('region',''))}</span>
          </div>
        </div>"""

    if len(findings) > limit:
        html += f'<div style="padding:14px 24px;color:var(--muted);font-size:12px;font-family:var(--mono)">+ {len(findings)-limit} more findings</div>'

    return html


def build_cost_rows(cost_findings: list) -> str:
    if not cost_findings:
        return """
        <tr><td colspan="4" style="text-align:center;color:var(--green);padding:32px;">
          ✅ No idle resources detected
        </td></tr>"""

    html = ""
    for f in sorted(cost_findings, key=lambda x: x.get("monthly_cost_usd", 0), reverse=True):
        label = RULE_LABELS.get(f.get("rule", ""), f.get("rule", ""))
        html += f"""
        <tr>
          <td>{esc(f.get('resource_id',''))}</td>
          <td style="color:var(--text-dim)">{esc(label)}</td>
          <td><span class="region-tag">{esc(f.get('region',''))}</span></td>
          <td>${f.get('monthly_cost_usd', 0):.2f}</td>
        </tr>"""
    return html


def build_rule_grid(security_findings: list) -> str:
    by_rule = group_by(security_findings, "rule")
    html = ""
    for rule in ALL_GOLDEN_RULES:
        label   = RULE_DISPLAY.get(rule, rule)
        count   = len(by_rule.get(rule, []))
        has_crit = any(f.get("severity") == "CRITICAL" for f in by_rule.get(rule, []))
        has_warn = any(f.get("severity") == "WARNING"  for f in by_rule.get(rule, []))

        if count == 0:
            status_cls  = "pass"
            status_icon = "✓"
            count_color = "var(--green)"
        elif has_crit:
            status_cls  = "fail"
            status_icon = "✗"
            count_color = "var(--red)"
        else:
            status_cls  = "warn"
            status_icon = "!"
            count_color = "var(--amber)"

        html += f"""
        <div class="rule-item">
          <div class="rule-status {status_cls}">{status_icon}</div>
          <div class="rule-name">{esc(label)}</div>
          <div class="rule-count" style="color:{count_color}">{count}</div>
        </div>"""
    return html


def build_account_rows(security_findings: list, cost_findings: list) -> str:
    all_findings = security_findings + cost_findings
    by_account   = group_by(all_findings, "account_id")
    max_count    = max((len(v) for v in by_account.values()), default=1)

    html = ""
    for account_id, findings in sorted(by_account.items()):
        name  = findings[0].get("account_name", account_id)
        count = len(findings)
        pct   = int((count / max_count) * 100)
        html += f"""
        <div class="account-row">
          <div>
            <div class="account-name">{esc(name)}</div>
            <div class="account-id">{esc(account_id)}</div>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%"></div>
          </div>
          <div class="account-tally">{count} issues</div>
        </div>"""
    return html or '<div style="padding:24px;color:var(--muted);font-size:13px;">No account data.</div>'


def build_region_tags(security_findings: list, cost_findings: list) -> str:
    all_findings = security_findings + cost_findings
    regions = sorted({f.get("region", "") for f in all_findings if f.get("region")})
    if not regions:
        return '<span class="region-tag" style="color:var(--muted)">no data</span>'

    show   = regions[:6]
    rest   = len(regions) - len(show)
    html   = "".join(f'<span class="region-tag">{esc(r)}</span>' for r in show)
    if rest > 0:
        html += f'<span class="region-tag" style="color:var(--muted)">+{rest} more</span>'
    return html


def format_scan_time(generated_at: str) -> str:
    try:
        dt = datetime.strptime(generated_at, "%Y-%m-%d_%H-%M-%S")
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return generated_at


# ── MAIN GENERATOR ────────────────────────────────────────────────────────────

def generate_dashboard():
    print("[DASHBOARD] Loading reports...")

    sec  = load_latest_json("findings_*.json")
    cost = load_latest_json("cost_waste_*.json")

    sec_findings  = sec.get("findings", [])
    cost_findings = cost.get("findings", [])

    sec_meta  = sec.get("metadata", {})
    cost_meta = cost.get("metadata", {})

    # ── Computed values ──
    critical_count  = sec_meta.get("critical_count", 0)
    warning_count   = sec_meta.get("warning_count", 0)
    total_monthly   = cost_meta.get("total_monthly_usd", 0.0)
    total_annual    = cost_meta.get("total_annual_usd", total_monthly * 12)
    idle_count      = cost_meta.get("total_findings", 0)
    scan_time       = format_scan_time(sec_meta.get("generated_at", ""))
    rules_passing   = sum(
        1 for rule in ALL_GOLDEN_RULES
        if not any(f.get("rule") == rule for f in sec_findings)
    )

    # ── Status banner ──
    if critical_count > 0:
        banner_cls  = "critical"
        banner_text = f"ACTION REQUIRED — {critical_count} critical violation(s) detected"
        dot_color   = "var(--red)"
    elif warning_count > 0:
        banner_cls  = "warning"
        banner_text = f"{warning_count} warning(s) — review when possible"
        dot_color   = "var(--amber)"
    else:
        banner_cls  = "clean"
        banner_text = "All Golden Rules passing — environment is clean"
        dot_color   = "var(--green)"

    # ── Account IDs for header ──
    all_acct_ids = sorted({
        f.get("account_id", "")
        for f in sec_findings + cost_findings
        if f.get("account_id")
    })
    acct_badge = " · ".join(all_acct_ids) if all_acct_ids else "No accounts scanned"

    # ── Severity totals for breakdown ──
    cost_total_fmt   = f"${total_monthly:,.2f}"
    annual_total_fmt = f"${total_annual:,.2f}"

    # ── Build HTML sections ──
    finding_rows  = build_finding_rows(
        [f for f in sec_findings if f.get("severity") == "CRITICAL"]
    )
    warning_rows  = build_finding_rows(
        [f for f in sec_findings if f.get("severity") == "WARNING"],
        limit=10
    )
    cost_rows     = build_cost_rows(cost_findings)
    rule_grid     = build_rule_grid(sec_findings)
    account_rows  = build_account_rows(sec_findings, cost_findings)
    region_tags   = build_region_tags(sec_findings, cost_findings)
    total_regions = len({f.get("region") for f in sec_findings + cost_findings if f.get("region")})
    total_accounts = len({f.get("account_id") for f in sec_findings + cost_findings if f.get("account_id")})

    # ── Inject into template ──
    html = HTML_TEMPLATE.format(
        SCAN_TIME        = esc(scan_time),
        ACCT_BADGE       = esc(acct_badge),
        BANNER_CLS       = banner_cls,
        BANNER_TEXT      = esc(banner_text),
        DOT_COLOR        = dot_color,
        TOTAL_ACCOUNTS   = total_accounts,
        TOTAL_REGIONS    = total_regions,
        CRITICAL_COUNT   = critical_count,
        WARNING_COUNT    = warning_count,
        MONTHLY_WASTE    = cost_total_fmt,
        ANNUAL_WASTE     = annual_total_fmt,
        IDLE_COUNT       = idle_count,
        RULES_PASSING    = rules_passing,
        FINDING_ROWS     = finding_rows,
        WARNING_ROWS     = warning_rows,
        COST_ROWS        = cost_rows,
        COST_TOTAL       = cost_total_fmt,
        ANNUAL_TOTAL     = annual_total_fmt,
        COST_COUNT       = idle_count,
        SEC_COUNT        = len(sec_findings),
        RULE_GRID        = rule_grid,
        ACCOUNT_ROWS     = account_rows,
        REGION_TAGS      = region_tags,
        CRITICAL_SEV     = critical_count,
        WARNING_SEV      = warning_count,
        WASTE_SEV        = idle_count,
    )

    REPORTS_DIR.mkdir(exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[DASHBOARD] Written → {OUTPUT_FILE}")
    return str(OUTPUT_FILE)


# ── HTML TEMPLATE ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetDevOps — Executive Security &amp; Cost Report</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:       #09090f; --surface: #111118; --surface2: #18181f;
    --border:   #23232e; --red: #ff3b5c; --amber: #ffb830;
    --green:    #00e07f; --blue: #3b8bff; --muted: #52526a;
    --text:     #e8e8f0; --text-dim: #8888a8;
    --mono:     'DM Mono', monospace;
    --display:  'Syne', sans-serif;
    --body:     'DM Sans', sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--body); font-weight: 300; min-height: 100vh; overflow-x: hidden; }}
  body::before {{ content: ''; position: fixed; inset: 0; background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E"); pointer-events: none; z-index: 0; opacity: 0.4; }}
  body::after {{ content: ''; position: fixed; inset: 0; background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px); background-size: 48px 48px; opacity: 0.3; pointer-events: none; z-index: 0; }}
  .wrapper {{ position: relative; z-index: 1; max-width: 1280px; margin: 0 auto; padding: 0 32px 80px; }}
  header {{ padding: 48px 0 40px; border-bottom: 1px solid var(--border); margin-bottom: 48px; display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; flex-wrap: wrap; }}
  .logo-tag {{ font-family: var(--mono); font-size: 11px; color: var(--muted); letter-spacing: 0.15em; text-transform: uppercase; }}
  h1 {{ font-family: var(--display); font-size: clamp(28px, 4vw, 48px); font-weight: 800; line-height: 1; letter-spacing: -0.02em; background: linear-gradient(135deg, var(--text) 0%, var(--text-dim) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
  .header-meta {{ text-align: right; display: flex; flex-direction: column; gap: 4px; }}
  .scan-time {{ font-family: var(--mono); font-size: 12px; color: var(--text-dim); }}
  .account-badge {{ font-family: var(--mono); font-size: 11px; color: var(--muted); background: var(--surface2); border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; display: inline-block; margin-top: 4px; }}
  .status-banner {{ display: flex; align-items: center; gap: 16px; padding: 20px 28px; border-radius: 12px; margin-bottom: 48px; border: 1px solid; position: relative; overflow: hidden; }}
  .status-banner.critical {{ background: rgba(255,59,92,0.06); border-color: rgba(255,59,92,0.25); }}
  .status-banner.warning  {{ background: rgba(255,184,48,0.06); border-color: rgba(255,184,48,0.25); }}
  .status-banner.clean    {{ background: rgba(0,224,127,0.06);  border-color: rgba(0,224,127,0.25); }}
  .status-banner::before {{ content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: {DOT_COLOR}; border-radius: 2px 0 0 2px; }}
  .status-dot {{ width: 10px; height: 10px; border-radius: 50%; background: {DOT_COLOR}; box-shadow: 0 0 12px {DOT_COLOR}; animation: pulse 2s ease-in-out infinite; flex-shrink: 0; }}
  @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.5; }} }}
  .status-text {{ font-family: var(--display); font-size: 16px; font-weight: 700; color: {DOT_COLOR}; }}
  .status-sub {{ font-size: 13px; color: var(--text-dim); margin-left: auto; }}
  .section-label {{ font-family: var(--mono); font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase; color: var(--muted); margin-bottom: 20px; display: flex; align-items: center; gap: 12px; }}
  .section-label::after {{ content: ''; flex: 1; height: 1px; background: var(--border); }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 48px; }}
  .kpi-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; position: relative; overflow: hidden; transition: border-color 0.2s, transform 0.2s; opacity: 0; transform: translateY(16px); animation: fadeUp 0.5s ease forwards; }}
  .kpi-card:hover {{ border-color: var(--muted); transform: translateY(-2px); }}
  .kpi-card::after {{ content: ''; position: absolute; inset: 0; background: radial-gradient(ellipse at top left, var(--accent-color, transparent) 0%, transparent 60%); opacity: 0.06; pointer-events: none; }}
  .kpi-card.red   {{ --accent-color: var(--red); }}
  .kpi-card.amber {{ --accent-color: var(--amber); }}
  .kpi-card.green {{ --accent-color: var(--green); }}
  .kpi-card.blue  {{ --accent-color: var(--blue); }}
  .kpi-label {{ font-family: var(--mono); font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--muted); margin-bottom: 12px; }}
  .kpi-value {{ font-family: var(--display); font-size: 42px; font-weight: 800; line-height: 1; letter-spacing: -0.03em; }}
  .kpi-card.red   .kpi-value {{ color: var(--red); }}
  .kpi-card.amber .kpi-value {{ color: var(--amber); }}
  .kpi-card.green .kpi-value {{ color: var(--green); }}
  .kpi-card.blue  .kpi-value {{ color: var(--blue); }}
  .kpi-sub {{ font-size: 12px; color: var(--text-dim); margin-top: 6px; }}
  .kpi-card:nth-child(1) {{ animation-delay: 0.05s; }} .kpi-card:nth-child(2) {{ animation-delay: 0.10s; }} .kpi-card:nth-child(3) {{ animation-delay: 0.15s; }} .kpi-card:nth-child(4) {{ animation-delay: 0.20s; }} .kpi-card:nth-child(5) {{ animation-delay: 0.25s; }}
  @keyframes fadeUp {{ to {{ opacity: 1; transform: translateY(0); }} }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 48px; }}
  @media (max-width: 768px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
  .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
  .panel-header {{ padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }}
  .panel-title {{ font-family: var(--display); font-size: 14px; font-weight: 700; letter-spacing: -0.01em; }}
  .panel-count {{ font-family: var(--mono); font-size: 11px; color: var(--muted); background: var(--surface2); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border); }}
  .panel-body {{ padding: 8px 0; }}
  .finding-row {{ display: flex; align-items: flex-start; gap: 14px; padding: 14px 24px; border-bottom: 1px solid var(--border); transition: background 0.15s; }}
  .finding-row:last-child {{ border-bottom: none; }}
  .finding-row:hover {{ background: var(--surface2); }}
  .sev-dot {{ width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }}
  .sev-dot.critical {{ background: var(--red); box-shadow: 0 0 6px var(--red); }}
  .sev-dot.warning  {{ background: var(--amber); }}
  .finding-info {{ flex: 1; min-width: 0; }}
  .finding-rule {{ font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-bottom: 3px; }}
  .finding-resource {{ font-size: 13px; color: var(--text); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .finding-detail {{ font-size: 11px; color: var(--muted); margin-top: 2px; line-height: 1.4; }}
  .finding-meta {{ text-align: right; flex-shrink: 0; }}
  .region-tag {{ font-family: var(--mono); font-size: 10px; color: var(--muted); background: var(--surface2); padding: 2px 6px; border-radius: 3px; border: 1px solid var(--border); }}
  .cost-table {{ width: 100%; border-collapse: collapse; }}
  .cost-table th {{ font-family: var(--mono); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); padding: 12px 24px; text-align: left; border-bottom: 1px solid var(--border); background: var(--surface2); }}
  .cost-table td {{ padding: 14px 24px; font-size: 13px; border-bottom: 1px solid var(--border); color: var(--text-dim); }}
  .cost-table tr:last-child td {{ border-bottom: none; }}
  .cost-table tr:hover td {{ background: var(--surface2); color: var(--text); }}
  .cost-table td:last-child {{ font-family: var(--mono); color: var(--blue); font-weight: 500; text-align: right; }}
  .cost-table tfoot td {{ font-weight: 500; color: var(--text); border-top: 1px solid var(--border); border-bottom: none; }}
  .cost-table tfoot td:last-child {{ color: var(--red); font-size: 15px; }}
  .rule-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0; }}
  .rule-item {{ display: flex; align-items: center; gap: 12px; padding: 14px 24px; border-bottom: 1px solid var(--border); border-right: 1px solid var(--border); }}
  .rule-item:nth-child(even) {{ border-right: none; }}
  .rule-item:nth-last-child(-n+2) {{ border-bottom: none; }}
  .rule-status {{ width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; flex-shrink: 0; }}
  .rule-status.pass {{ background: rgba(0,224,127,0.15); color: var(--green); }}
  .rule-status.fail {{ background: rgba(255,59,92,0.15);  color: var(--red); }}
  .rule-status.warn {{ background: rgba(255,184,48,0.15);  color: var(--amber); }}
  .rule-name {{ font-size: 12px; color: var(--text-dim); line-height: 1.3; }}
  .rule-count {{ margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--muted); }}
  .account-row {{ display: flex; align-items: center; gap: 16px; padding: 16px 24px; border-bottom: 1px solid var(--border); }}
  .account-row:last-child {{ border-bottom: none; }}
  .account-name {{ font-size: 13px; font-weight: 500; min-width: 140px; }}
  .account-id {{ font-family: var(--mono); font-size: 10px; color: var(--muted); }}
  .bar-track {{ flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 3px; background: linear-gradient(90deg, var(--red), var(--amber)); }}
  .account-tally {{ font-family: var(--mono); font-size: 12px; color: var(--text-dim); min-width: 60px; text-align: right; }}
  footer {{ margin-top: 64px; padding-top: 24px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  .footer-brand {{ font-family: var(--mono); font-size: 11px; color: var(--muted); }}
  .footer-note {{ font-size: 11px; color: var(--muted); }}
</style>
</head>
<body>
<div class="wrapper">

  <header>
    <div>
      <div class="logo-tag">NetDevOps // Executive Report</div>
      <h1>Security &amp; Cost Intelligence</h1>
    </div>
    <div class="header-meta">
      <span class="scan-time">Scan: {SCAN_TIME}</span>
      <span class="account-badge">{ACCT_BADGE}</span>
    </div>
  </header>

  <div class="status-banner {BANNER_CLS}">
    <div class="status-dot"></div>
    <span class="status-text">{BANNER_TEXT}</span>
    <span class="status-sub">{TOTAL_ACCOUNTS} account(s) · {TOTAL_REGIONS} region(s) scanned</span>
  </div>

  <div class="section-label">Overview</div>
  <div class="kpi-grid">
    <div class="kpi-card red">
      <div class="kpi-label">Critical</div>
      <div class="kpi-value">{CRITICAL_COUNT}</div>
      <div class="kpi-sub">Require immediate action</div>
    </div>
    <div class="kpi-card amber">
      <div class="kpi-label">Warnings</div>
      <div class="kpi-value">{WARNING_COUNT}</div>
      <div class="kpi-sub">Review when possible</div>
    </div>
    <div class="kpi-card blue">
      <div class="kpi-label">Monthly Waste</div>
      <div class="kpi-value">{MONTHLY_WASTE}</div>
      <div class="kpi-sub">{ANNUAL_WASTE}/year projected</div>
    </div>
    <div class="kpi-card amber">
      <div class="kpi-label">Idle Resources</div>
      <div class="kpi-value">{IDLE_COUNT}</div>
      <div class="kpi-sub">Not earning their cost</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-label">Rules Passing</div>
      <div class="kpi-value">{RULES_PASSING}</div>
      <div class="kpi-sub">of 8 Golden Rules clean</div>
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">🔴 Critical Violations</span>
        <span class="panel-count">{CRITICAL_COUNT} findings</span>
      </div>
      <div class="panel-body">{FINDING_ROWS}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">🟡 Warnings</span>
        <span class="panel-count">{WARNING_COUNT} findings</span>
      </div>
      <div class="panel-body">{WARNING_ROWS}</div>
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">💸 Cost Waste</span>
        <span class="panel-count">{COST_TOTAL}/month</span>
      </div>
      <div class="panel-body">
        <table class="cost-table">
          <thead>
            <tr><th>Resource</th><th>Type</th><th>Region</th><th>$/mo</th></tr>
          </thead>
          <tbody>{COST_ROWS}</tbody>
          <tfoot>
            <tr>
              <td colspan="3"><strong>Total Monthly Waste</strong></td>
              <td><strong>{COST_TOTAL}</strong></td>
            </tr>
            <tr>
              <td colspan="3" style="color:var(--muted);font-size:11px">Annual projection</td>
              <td style="color:var(--amber);font-size:12px">{ANNUAL_TOTAL}/yr</td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Golden Rules Coverage</span>
        <span class="panel-count">{RULES_PASSING} / 8 passing</span>
      </div>
      <div class="rule-grid">{RULE_GRID}</div>
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Account Breakdown</span>
        <span class="panel-count">{TOTAL_ACCOUNTS} accounts</span>
      </div>
      <div class="panel-body">
        {ACCOUNT_ROWS}
        <div style="padding:20px 24px;border-top:1px solid var(--border)">
          <div class="section-label" style="margin-bottom:16px">Severity breakdown</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <div style="flex:1;background:rgba(255,59,92,0.08);border:1px solid rgba(255,59,92,0.2);border-radius:8px;padding:14px;text-align:center">
              <div style="font-family:var(--mono);font-size:24px;font-weight:700;color:var(--red)">{CRITICAL_SEV}</div>
              <div style="font-size:11px;color:var(--muted);margin-top:4px">Critical</div>
            </div>
            <div style="flex:1;background:rgba(255,184,48,0.08);border:1px solid rgba(255,184,48,0.2);border-radius:8px;padding:14px;text-align:center">
              <div style="font-family:var(--mono);font-size:24px;font-weight:700;color:var(--amber)">{WARNING_SEV}</div>
              <div style="font-size:11px;color:var(--muted);margin-top:4px">Warning</div>
            </div>
            <div style="flex:1;background:rgba(59,139,255,0.08);border:1px solid rgba(59,139,255,0.2);border-radius:8px;padding:14px;text-align:center">
              <div style="font-family:var(--mono);font-size:24px;font-weight:700;color:var(--blue)">{WASTE_SEV}</div>
              <div style="font-size:11px;color:var(--muted);margin-top:4px">Waste</div>
            </div>
          </div>
        </div>
        <div style="padding:16px 24px;border-top:1px solid var(--border)">
          <div class="section-label" style="margin-bottom:12px">Regions scanned</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">{REGION_TAGS}</div>
        </div>
      </div>
    </div>
  </div>

  <footer>
    <div class="footer-brand">NetDevOps Self-Healing Platform · github.com/yogi301189/network-auditor</div>
    <div class="footer-note">Read-only scan · No changes made · Auto-remediation runs separately via Lambda</div>
  </footer>

</div>
</body>
</html>"""


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    path = generate_dashboard()
    print(f"[DASHBOARD] Open in browser: {path}")