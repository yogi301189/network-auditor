"""
auditor/pdf_report.py
======================
Generates a professional PDF security audit report from the
findings JSON produced by report.py.

Uses reportlab (industry standard Python PDF library) instead of
fpdf — better table support, proper color handling, and cleaner layout.

Usage:
    python -m auditor.pdf_report reports/findings_2026-02-19.json

Or integrated into main.py automatically after each scan.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ── BRAND COLOURS ─────────────────────────────────────────────────────────────

DARK_NAVY    = colors.HexColor("#0d1b2a")
MID_BLUE     = colors.HexColor("#1b4f72")
LIGHT_BLUE   = colors.HexColor("#d6eaf8")
CRITICAL_RED = colors.HexColor("#c0392b")
CRITICAL_BG  = colors.HexColor("#fadbd8")
WARNING_ORG  = colors.HexColor("#d35400")
WARNING_BG   = colors.HexColor("#fdebd0")
SUCCESS_GRN  = colors.HexColor("#1e8449")
SUCCESS_BG   = colors.HexColor("#d5f5e3")
LIGHT_GREY   = colors.HexColor("#f2f3f4")
MID_GREY     = colors.HexColor("#aab7b8")
WHITE        = colors.white


# ── STYLES ────────────────────────────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=28, leading=34,
            textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            spaceAfter=6,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=13, leading=18,
            textColor=colors.HexColor("#aed6f1"),
            alignment=TA_CENTER,
            fontName="Helvetica",
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            fontSize=14, leading=18,
            textColor=MID_BLUE,
            fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=10, leading=14,
            textColor=colors.HexColor("#2c3e50"),
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "critical_label": ParagraphStyle(
            "critical_label",
            fontSize=9, leading=12,
            textColor=CRITICAL_RED,
            fontName="Helvetica-Bold",
        ),
        "warning_label": ParagraphStyle(
            "warning_label",
            fontSize=9, leading=12,
            textColor=WARNING_ORG,
            fontName="Helvetica-Bold",
        ),
        "mono": ParagraphStyle(
            "mono",
            fontSize=8, leading=11,
            textColor=colors.HexColor("#2c3e50"),
            fontName="Courier",
        ),
        "footer_text": ParagraphStyle(
            "footer_text",
            fontSize=8,
            textColor=MID_GREY,
            alignment=TA_CENTER,
            fontName="Helvetica",
        ),
    }
    return styles


# ── PAGE TEMPLATE ─────────────────────────────────────────────────────────────

class ReportCanvas:
    """Adds header bar and footer to every page."""

    def __init__(self, scan_time: str):
        self.scan_time = scan_time

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # ── Top header bar ──
        canvas.setFillColor(DARK_NAVY)
        canvas.rect(0, h - 20*mm, w, 20*mm, fill=1, stroke=0)

        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(15*mm, h - 12*mm, "NetDevOps Network Auditor")

        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#aed6f1"))
        canvas.drawRightString(w - 15*mm, h - 12*mm, f"Scan: {self.scan_time}")

        # ── Bottom footer ──
        canvas.setFillColor(LIGHT_GREY)
        canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)

        canvas.setFillColor(MID_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(15*mm, 4*mm, "CONFIDENTIAL — Internal Use Only")
        canvas.drawCentredString(w/2, 4*mm, f"Page {doc.page}")
        canvas.drawRightString(w - 15*mm, 4*mm, "github.com/yogi301189/network-auditor")

        canvas.restoreState()


# ── COVER PAGE ────────────────────────────────────────────────────────────────

def build_cover(styles, metadata: dict) -> list:
    elements = []

    # Top spacer to push content down
    elements.append(Spacer(1, 30*mm))

    # Dark navy title block
    title_data = [[
        Paragraph(
            "NetDevOps Security Audit<br/>Multi-Account AWS Security Report",
            ParagraphStyle(
                "cover_title",
                fontSize=24, leading=32,
                textColor=WHITE,
                fontName="Helvetica-Bold",
                alignment=TA_CENTER,
                spaceAfter=0,
            )
        )
    ]]
    title_table = Table(title_data, colWidths=[170*mm])
    title_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 14*mm),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14*mm),
        ("LEFTPADDING",   (0,0), (-1,-1), 10*mm),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10*mm),
    ]))
    elements.append(title_table)
    elements.append(Spacer(1, 10*mm))

    elements.append(HRFlowable(width="100%", thickness=2, color=MID_BLUE, spaceAfter=8*mm))

    # Meta table
    meta_rows = [
        ["Scan Date",        metadata.get("scan_time", "N/A")],
        ["Accounts Scanned", metadata.get("accounts_scanned", "N/A")],
        ["Total Violations", str(metadata.get("total_violations", 0))],
        ["Critical",         str(metadata.get("critical_count", 0))],
        ["Warnings",         str(metadata.get("warning_count", 0))],
        ["Generated By",     "Network Auditor — NetDevOps Platform"],
    ]

    meta_table = Table(meta_rows, colWidths=[55*mm, 115*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",       (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",       (0,0), (-1,-1), 10),
        ("TEXTCOLOR",      (0,0), (0,-1), MID_BLUE),
        ("TEXTCOLOR",      (1,0), (1,-1), colors.HexColor("#2c3e50")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [WHITE, LIGHT_GREY]),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("LEFTPADDING",    (0,0), (-1,-1), 8),
        ("BOX",            (0,0), (-1,-1), 0.5, MID_GREY),
        ("INNERGRID",      (0,0), (-1,-1), 0.25, MID_GREY),
    ]))
    elements.append(meta_table)
    elements.append(PageBreak())

    return elements


# ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────────

def build_executive_summary(styles, metadata: dict, findings: list) -> list:
    elements = []
    elements.append(Paragraph("Executive Summary", styles["section_heading"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=LIGHT_BLUE, spaceAfter=8))

    total     = metadata.get("total_violations", 0)
    critical  = metadata.get("critical_count", 0)
    warnings  = metadata.get("warning_count", 0)

    if total == 0:
        summary_text = (
            "This automated scan found <b>no violations</b> across all scanned accounts and regions. "
            "All 8 Golden Rules passed. The network is clean and compliant."
        )
        bg = SUCCESS_BG
        fg = SUCCESS_GRN
        status = "CLEAN"
    elif critical > 0:
        summary_text = (
            f"This automated scan identified <b>{total} violation(s)</b> across all scanned accounts, "
            f"including <b>{critical} critical issue(s)</b> that require immediate attention. "
            f"Critical violations represent active security risks that could lead to data breaches or "
            f"unauthorised access if not remediated promptly."
        )
        bg = CRITICAL_BG
        fg = CRITICAL_RED
        status = "ACTION REQUIRED"
    else:
        summary_text = (
            f"This automated scan identified <b>{total} warning(s)</b> across all scanned accounts. "
            f"No critical violations were found. Warnings represent hygiene and cost issues "
            f"that should be tracked and resolved in the next maintenance cycle."
        )
        bg = WARNING_BG
        fg = WARNING_ORG
        status = "REVIEW RECOMMENDED"

    # Status banner
    status_data = [[f"Status: {status}"]]
    status_table = Table(status_data, colWidths=[170*mm])
    status_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("TEXTCOLOR",     (0,0), (-1,-1), fg),
        ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 12),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("BOX",           (0,0), (-1,-1), 1, fg),
    ]))
    elements.append(status_table)
    elements.append(Spacer(1, 6*mm))

    elements.append(Paragraph(summary_text, styles["body"]))
    elements.append(Spacer(1, 6*mm))

    # Scorecard table
    scorecard = [
        ["Metric", "Count"],
        ["Total Violations", str(total)],
        ["Critical", str(critical)],
        ["Warnings", str(warnings)],
        ["Accounts Scanned", metadata.get("accounts_scanned", "N/A")],
        ["Regions Scanned", "17"],
        ["Golden Rules Checked", "8"],
    ]

    sc_table = Table(scorecard, colWidths=[100*mm, 70*mm])
    sc_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_NAVY),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("ALIGN",         (1,0), (1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("BOX",           (0,0), (-1,-1), 0.5, MID_GREY),
        ("INNERGRID",     (0,0), (-1,-1), 0.25, MID_GREY),
    ]))
    elements.append(sc_table)
    elements.append(PageBreak())

    return elements


# ── FINDINGS DETAIL ───────────────────────────────────────────────────────────

def build_findings(styles, findings: list) -> list:
    elements = []

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    warnings = [f for f in findings if f.get("severity") == "WARNING"]

    # ── Critical section ──
    if critical:
        elements.append(Paragraph("Critical Violations", styles["section_heading"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=CRITICAL_RED, spaceAfter=6))
        elements.append(Paragraph(
            "The following violations represent active security risks requiring immediate remediation.",
            styles["body"]
        ))
        elements.append(Spacer(1, 4*mm))

        table_data = [["#", "Rule", "Resource", "Region", "Account", "Detail"]]
        for i, f in enumerate(critical, 1):
            table_data.append([
                str(i),
                f.get("rule", ""),
                Paragraph(f.get("resource_id", ""), styles["mono"]),
                f.get("region", ""),
                f.get("account_name", f.get("account_id", "Primary")),
                Paragraph(f.get("detail", ""), styles["body"]),
            ])

        col_widths = [8*mm, 35*mm, 32*mm, 22*mm, 25*mm, 48*mm]
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), CRITICAL_RED),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, CRITICAL_BG]),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 4),
            ("BOX",           (0,0), (-1,-1), 0.5, CRITICAL_RED),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, MID_GREY),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8*mm))

    # ── Warnings section ──
    if warnings:
        elements.append(Paragraph("Warnings", styles["section_heading"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=WARNING_ORG, spaceAfter=6))
        elements.append(Paragraph(
            "The following warnings represent hygiene and cost issues. Not urgent but should be tracked.",
            styles["body"]
        ))
        elements.append(Spacer(1, 4*mm))

        table_data = [["#", "Rule", "Resource", "Region", "Account", "Detail"]]
        for i, f in enumerate(warnings, 1):
            table_data.append([
                str(i),
                f.get("rule", ""),
                Paragraph(f.get("resource_id", ""), styles["mono"]),
                f.get("region", ""),
                f.get("account_name", f.get("account_id", "Primary")),
                Paragraph(f.get("detail", ""), styles["body"]),
            ])

        col_widths = [8*mm, 35*mm, 32*mm, 22*mm, 25*mm, 48*mm]
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), WARNING_ORG),
            ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, WARNING_BG]),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 4),
            ("BOX",           (0,0), (-1,-1), 0.5, WARNING_ORG),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, MID_GREY),
        ]))
        elements.append(t)

    if not critical and not warnings:
        clean_data = [["All 8 Golden Rules Passed — Network is Clean"]]
        clean_table = Table(clean_data, colWidths=[170*mm])
        clean_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), SUCCESS_BG),
            ("TEXTCOLOR",     (0,0), (-1,-1), SUCCESS_GRN),
            ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 12),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0), (-1,-1), 12),
            ("BOTTOMPADDING", (0,0), (-1,-1), 12),
            ("BOX",           (0,0), (-1,-1), 1, SUCCESS_GRN),
        ]))
        elements.append(clean_table)

    return elements


# ── MAIN GENERATOR ────────────────────────────────────────────────────────────

def generate_pdf(json_path: str, output_path: str = None) -> str:
    """
    Reads a findings JSON file and generates a professional PDF report.

    json_path   : path to findings_*.json produced by report.py
    output_path : where to save the PDF (default: same folder as JSON)
    """
    # Load findings
    with open(json_path) as f:
        data = json.load(f)

    findings  = data.get("findings", [])
    scan_meta = data.get("metadata", {})
    scan_time = scan_meta.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M UTC"))

    # Build metadata summary
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    warning_count  = sum(1 for f in findings if f.get("severity") == "WARNING")
    accounts       = list({f.get("account_name", "Primary") for f in findings}) or ["Primary"]

    metadata = {
        "scan_time":        scan_time,
        "total_violations": len(findings),
        "critical_count":   critical_count,
        "warning_count":    warning_count,
        "accounts_scanned": ", ".join(accounts) if accounts else "Primary",
    }

    # Output path
    if not output_path:
        output_path = str(Path(json_path).parent / f"audit_report_{datetime.now().strftime('%Y-%m-%d')}.pdf")

    # Build PDF
    doc = SimpleDocTemplate(
        output_path,
        pagesize      = A4,
        topMargin     = 25*mm,
        bottomMargin  = 20*mm,
        leftMargin    = 20*mm,
        rightMargin   = 20*mm,
        title         = "NetDevOps Security Audit Report",
        author        = "Network Auditor",
    )

    styles   = build_styles()
    canvas_fn = ReportCanvas(scan_time)
    story    = []

    story += build_cover(styles, metadata)
    story += build_executive_summary(styles, metadata, findings)
    story += build_findings(styles, findings)

    doc.build(story, onFirstPage=canvas_fn, onLaterPages=canvas_fn)

    print(f"PDF report generated: {output_path}")
    return output_path


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m auditor.pdf_report reports/findings_*.json")
        sys.exit(1)

    json_path = sys.argv[1]
    generate_pdf(json_path)