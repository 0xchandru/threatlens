from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.units import mm
from io import BytesIO
import datetime

COLOR_CRITICAL   = HexColor("#DC2626")
COLOR_MALICIOUS  = HexColor("#EA580C")
COLOR_SUSPICIOUS = HexColor("#CA8A04")
COLOR_LOW        = HexColor("#2563EB")
COLOR_CLEAN      = HexColor("#16A34A")
COLOR_HEADER     = HexColor("#0F172A")
COLOR_ACCENT     = HexColor("#0EA5E9")

RISK_COLORS = {
    "critical":   COLOR_CRITICAL,
    "malicious":  COLOR_MALICIOUS,
    "suspicious": COLOR_SUSPICIOUS,
    "low":        COLOR_LOW,
    "clean":      COLOR_CLEAN,
}


def generate_ioc_report(scan_data: dict, notes: list, mitre_techniques: list) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    story.append(Paragraph(
        "<font color='#0EA5E9' size='22'><b>ThreatLens</b></font> "
        "<font color='#64748B' size='14'>Threat Intelligence Report</font>",
        styles["Normal"]
    ))
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", color=COLOR_ACCENT, thickness=2))
    story.append(Spacer(1, 4*mm))

    ioc   = scan_data.get("ioc", {})
    score = scan_data.get("score", 0)
    risk  = scan_data.get("risk_level", "clean")
    risk_color = RISK_COLORS.get(risk, black)

    summary_data = [
        ["IOC Value",    ioc.get("value", "N/A")],
        ["Type",         str(ioc.get("type", "")).upper()],
        ["Risk Level",   risk.upper()],
        ["Threat Score", f"{score:.1f} / 100"],
        ["Confidence",   scan_data.get("confidence", "medium").upper()],
        ["Scan Time",    datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Query Time",   f"{scan_data.get('query_time_ms', 0)} ms (5 sources parallel)"],
    ]

    summary_table = Table(summary_data, colWidths=[50*mm, 120*mm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME",       (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",      (1, 2), (1, 2), risk_color),
        ("FONTNAME",       (1, 2), (1, 2), "Helvetica-Bold"),
        ("FONTSIZE",       (1, 2), (1, 2), 11),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [HexColor("#F8FAFC"), white]),
        ("GRID",           (0, 0), (-1, -1), 0.5, HexColor("#E2E8F0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    story.append(Paragraph("<b>Score Breakdown by Source</b>", styles["Heading2"]))
    story.append(Spacer(1, 3*mm))

    breakdown = scan_data.get("breakdown", {})
    weights = {"virustotal": 32, "abuseipdb": 25, "alienvault": 22, "urlhaus": 12, "greynoise": 9}
    bd_rows = [["Source", "Score Contribution", "Max Weight", "% Utilized"]]

    for source, contrib in breakdown.items():
        max_w = weights.get(source, 0)
        pct   = f"{(contrib/max_w*100):.0f}%" if max_w > 0 else "—"
        bd_rows.append([source.upper(), f"{contrib:.2f}", f"{max_w}", pct])

    bd_table = Table(bd_rows, colWidths=[45*mm, 40*mm, 40*mm, 40*mm])
    bd_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), COLOR_HEADER),
        ("TEXTCOLOR",      (0, 0), (-1, 0), white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F8FAFC"), white]),
        ("GRID",           (0, 0), (-1, -1), 0.5, HexColor("#CBD5E1")),
        ("ALIGN",          (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ]))
    story.append(bd_table)
    story.append(Spacer(1, 8*mm))

    if mitre_techniques:
        story.append(Paragraph("<b>MITRE ATT&CK Mappings</b>", styles["Heading2"]))
        story.append(Spacer(1, 3*mm))

        mitre_rows = [["Technique ID", "Technique", "Tactic", "Confidence", "Source"]]
        for t in mitre_techniques:
            mitre_rows.append([
                t.get("technique_id", ""), t.get("technique", ""),
                t.get("tactic", ""), t.get("confidence", "").upper(), t.get("source", "")
            ])

        mitre_table = Table(mitre_rows, colWidths=[25*mm, 50*mm, 35*mm, 25*mm, 30*mm])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0), HexColor("#1E3A5F")),
            ("TEXTCOLOR",      (0, 0), (-1, 0), white),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#EFF6FF"), white]),
            ("GRID",           (0, 0), (-1, -1), 0.5, HexColor("#BFDBFE")),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 8*mm))

    if notes:
        story.append(Paragraph("<b>Analyst Notes</b>", styles["Heading2"]))
        for note in notes:
            story.append(Paragraph(
                f"<font size='8' color='#64748B'>{note.get('analyst', 'analyst')} · "
                f"{note.get('created_at', '')}</font>",
                styles["Normal"]
            ))
            story.append(Paragraph(note.get("note", ""), styles["Normal"]))
            story.append(Spacer(1, 3*mm))

    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", color=HexColor("#E2E8F0")))
    story.append(Paragraph(
        "<font size='8' color='#94A3B8'>Generated by ThreatLens · "
        "Data sourced from VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, GreyNoise</font>",
        styles["Normal"]
    ))

    doc.build(story)
    return buffer.getvalue()
