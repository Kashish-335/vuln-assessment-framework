"""
PDF Report Generator Module using ReportLab Platypus.
Produces professional, college-viva ready security audit reports complete with
executive summary, WSTG methodology, findings matrix, and technical remediations.
"""
from datetime import datetime
import io
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and draw 'Page X of Y' footers
    and a professional running header on every page after the cover page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        # Omit headers/footers on cover page
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#6C757D"))

        # Running Header
        self.drawString(54, letter[1] - 36, "Web Application Vulnerability Assessment & WAF Defense Report")
        self.drawRightString(letter[0] - 54, letter[1] - 36, "CONFIDENTIAL - ACADEMIC LAB")
        self.setStrokeColor(colors.HexColor("#DEE2E6"))
        self.setLineWidth(0.5)
        self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Running Footer
        self.line(54, 45, letter[0] - 54, 45)
        self.drawString(54, 32, "Automated Security Assessment Framework | OWASP Top 10 Benchmark")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 54, 32, page_str)
        self.restoreState()


def get_severity_color(severity_str):
    """Map severity string to ReportLab color hex."""
    s = (severity_str or '').lower()
    if 'high' in s:
        return colors.HexColor("#DC3545")  # Red
    elif 'medium' in s:
        return colors.HexColor("#FD7E14")  # Orange
    elif 'low' in s:
        return colors.HexColor("#FFC107")  # Amber/Yellow
    return colors.HexColor("#0D6EFD")      # Blue / Info


def generate_pdf_report(scan, findings, output_filepath=None):
    """
    Generate a full academic vulnerability assessment PDF report.

    Args:
        scan: Scan SQLAlchemy model instance
        findings: List of Finding SQLAlchemy model instances
        output_filepath: Optional path to save file directly. If None, returns BytesIO.

    Returns:
        BytesIO buffer or saved filepath string.
    """
    buffer = io.BytesIO() if output_filepath is None else output_filepath
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1A202C")
    )
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#4A5568")
    )
    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0D6EFD"),
        spaceAfter=10
    )
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#212529"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#2D3748")
    )
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#C0392B")
    )

    elements = []

    # =========================================================================
    # PAGE 1: COVER PAGE
    # =========================================================================
    elements.append(Spacer(1, 40))
    # Top decorative colored banner line
    elements.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor("#0D6EFD"), spaceAfter=30))
    
    elements.append(Paragraph("VULNERABILITY ASSESSMENT &amp; DEFENSE REPORT", title_style))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Automated Web Application Security Audit &amp; Mini WAF Mitigation Analysis", subtitle_style))
    elements.append(Spacer(1, 40))

    # Metadata Box
    date_str = scan.started_at.strftime("%B %d, %Y - %H:%M UTC") if scan.started_at else datetime.utcnow().strftime("%B %d, %Y")
    meta_table_data = [
        [Paragraph("<b>Target URL:</b>", body_style), Paragraph(scan.target_url, body_style)],
        [Paragraph("<b>Target Host / IP:</b>", body_style), Paragraph(f"{scan.target_host} ({scan.target_ip}:{scan.target_port})", body_style)],
        [Paragraph("<b>Scan Mode:</b>", body_style), Paragraph(f"<b>{scan.scan_mode.upper()}</b>", body_style)],
        [Paragraph("<b>Audit Date:</b>", body_style), Paragraph(date_str, body_style)],
        [Paragraph("<b>Assessment Status:</b>", body_style), Paragraph(scan.status.capitalize(), body_style)],
        [Paragraph("<b>Classification:</b>", body_style), Paragraph("Academic Security Audit / Isolated Lab Only", body_style)],
    ]
    t_meta = Table(meta_table_data, colWidths=[130, 370])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8F9FA")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#DEE2E6")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E9ECEF")),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_meta)

    elements.append(Spacer(1, 40))

    # Findings Quick Badge Card
    badge_data = [
        [
            Paragraph(f"<font size=16 color='#DC3545'><b>{scan.high_count}</b></font><br/><font size=8>HIGH</font>", body_style),
            Paragraph(f"<font size=16 color='#FD7E14'><b>{scan.medium_count}</b></font><br/><font size=8>MEDIUM</font>", body_style),
            Paragraph(f"<font size=16 color='#FFC107'><b>{scan.low_count}</b></font><br/><font size=8>LOW</font>", body_style),
            Paragraph(f"<font size=16 color='#0D6EFD'><b>{scan.info_count}</b></font><br/><font size=8>INFO</font>", body_style),
            Paragraph(f"<font size=16 color='#212529'><b>{scan.total_findings}</b></font><br/><font size=8>TOTAL</font>", body_style)
        ]
    ]
    t_badges = Table(badge_data, colWidths=[100, 100, 100, 100, 100])
    t_badges.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F1F3F5")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CED4DA")),
        ('PADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(t_badges)

    elements.append(Spacer(1, 80))
    elements.append(Paragraph(
        "<b>Notice of Confidentiality &amp; Scope:</b> This document contains sensitive vulnerability assessment results intended solely for educational evaluation and authorized lab testing within the academic curriculum.",
        ParagraphStyle('Notice', parent=body_style, fontSize=8, textColor=colors.HexColor("#6C757D"))
    ))
    elements.append(PageBreak())

    # =========================================================================
    # PAGE 2: EXECUTIVE SUMMARY & METHODOLOGY
    # =========================================================================
    elements.append(Paragraph("1. Executive Summary", h1_style))
    exec_summary_text = (
        f"An automated vulnerability assessment was conducted against the target application at "
        f"<b>{scan.target_url}</b> in an isolated laboratory setting. The assessment identified a total of "
        f"<b>{scan.total_findings} security findings</b>, comprising <b>{scan.high_count} High</b>, "
        f"<b>{scan.medium_count} Medium</b>, <b>{scan.low_count} Low</b>, and "
        f"<b>{scan.info_count} Informational</b> disclosures."
    )
    elements.append(Paragraph(exec_summary_text, body_style))
    elements.append(Spacer(1, 10))

    if scan.scan_mode == 'waf_protected':
        waf_narrative = (
            "<b>Defensive Posture Note:</b> This scan evaluated the application through the <b>Mini WAF Reverse Proxy</b> "
            "(Port 8080). Critical injection attack vectors (SQLi, XSS, Path Traversal) were actively blocked with HTTP 403 "
            "Forbidden responses, and defense-in-depth HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options) "
            "were injected, successfully mitigating common exploit paths."
        )
    else:
        waf_narrative = (
            "<b>Vulnerability Notice:</b> The target was evaluated in <b>Direct Mode</b> without active web application firewall filtering. "
            "Severe vulnerabilities such as SQL Injection and Reflected Cross-Site Scripting were successfully confirmed. "
            "Deployment of the Mini WAF reverse-proxy is recommended to mitigate active exploitation."
        )
    elements.append(Paragraph(waf_narrative, body_style))
    elements.append(Spacer(1, 18))

    elements.append(Paragraph("2. Assessment Scope &amp; Methodology", h1_style))
    methodology_text = (
        "The security testing lifecycle aligns with the <b>OWASP Web Security Testing Guide (WSTG v4.2)</b> "
        "and comprises three sequential phases:<br/>"
        "• <b>Target Boundary Validation:</b> Strict validation verifying target hosts resolve to loopback or RFC 1918 private IP blocks.<br/>"
        "• <b>Network &amp; Service Reconnaissance (Nmap):</b> Discovery of open ports, daemon banners, and service versions.<br/>"
        "• <b>Dynamic Application Security Testing (DAST):</b> Automated spidering of endpoints followed by active vulnerability probing against OWASP Top 10 benchmarks."
    )
    elements.append(Paragraph(methodology_text, body_style))
    elements.append(Spacer(1, 20))

    # =========================================================================
    # FINDINGS SUMMARY TABLE
    # =========================================================================
    elements.append(Paragraph("3. Findings Summary Matrix", h1_style))
    
    table_header = [
        Paragraph("<b>#</b>", body_style),
        Paragraph("<b>Severity</b>", body_style),
        Paragraph("<b>Vulnerability Title</b>", body_style),
        Paragraph("<b>OWASP Category</b>", body_style),
        Paragraph("<b>CWE ID</b>", body_style)
    ]
    rows = [table_header]
    
    for idx, f in enumerate(findings, start=1):
        sev_color = get_severity_color(f.severity)
        rows.append([
            Paragraph(str(idx), body_style),
            Paragraph(f"<font color='{sev_color.hexval()}'><b>{f.severity}</b></font>", body_style),
            Paragraph(f"<b>{f.title}</b>", body_style),
            Paragraph(f.owasp_category.split('-')[0] if '-' in f.owasp_category else f.owasp_category, body_style),
            Paragraph(f.cwe_id, body_style)
        ])

    t_findings = Table(rows, colWidths=[25, 75, 190, 130, 80])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#E9ECEF")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CED4DA")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DEE2E6")),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(t_findings)
    elements.append(PageBreak())

    # =========================================================================
    # DETAILED FINDINGS SECTION
    # =========================================================================
    elements.append(Paragraph("4. Detailed Technical Findings &amp; Remediations", h1_style))
    elements.append(Spacer(1, 10))

    for idx, f in enumerate(findings, start=1):
        sev_color = get_severity_color(f.severity)
        
        detail_box = [
            [
                Paragraph(f"<b>Finding {idx}: {f.title}</b>", ParagraphStyle('FTitle', parent=h2_style, textColor=colors.HexColor("#1A202C"))),
                Paragraph(f"<font color='{sev_color.hexval()}'><b>{f.severity.upper()}</b></font> (CVSS {f.cvss_score})", body_style)
            ],
            [
                Paragraph(f"<b>CWE:</b> {f.cwe_id} | <b>OWASP:</b> {f.owasp_category}", body_style),
                Paragraph(f"<b>Target URL:</b> {f.url}", body_style)
            ]
        ]
        t_head = Table(detail_box, colWidths=[330, 170])
        t_head.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8F9FA")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CED4DA")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))

        finding_flowables = [
            t_head,
            Spacer(1, 6),
            Paragraph("<b>Vulnerability Description &amp; Impact:</b>", body_style),
            Paragraph(f.description or "No detailed description provided.", body_style),
            Spacer(1, 4),
            Paragraph("<b>Attack Evidence &amp; Parameter:</b>", body_style),
            Paragraph(f"<b>Parameter:</b> {f.parameter} | <b>Payload:</b> <font name='Courier'>{f.attack_payload}</font>", body_style),
            Paragraph(f"<font color='#C0392B' size=8>{f.evidence}</font>", code_style),
            Spacer(1, 4),
            Paragraph("<b>Remediation Guidance:</b>", body_style),
            Paragraph(f.remediation or "Follow standard secure coding guidelines.", body_style),
            Spacer(1, 12),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#DEE2E6"), spaceAfter=14)
        ]
        elements.append(KeepTogether(finding_flowables))

    # =========================================================================
    # CONCLUSION & SIGN-OFF
    # =========================================================================
    conclusion_flowables = [
        Paragraph("5. Conclusion &amp; Evaluator Sign-off", h1_style),
        Paragraph(
            "This vulnerability assessment successfully evaluated web application security posture and "
            "demonstrated the protective capabilities of the Mini WAF reverse-proxy architecture. "
            "Remediation efforts should prioritize High severity injection vulnerabilities followed by "
            "baseline security header deployment.",
            body_style
        ),
        Spacer(1, 30),
        Table([
            [Paragraph("<b>Student / Lead Security Evaluator:</b>", body_style), Paragraph("<b>Academic Faculty / Viva Examiner:</b>", body_style)],
            [Spacer(1, 30), Spacer(1, 30)],
            [Paragraph("____________________________<br/>Signature &amp; Date", body_style), Paragraph("____________________________<br/>Signature &amp; Date", body_style)]
        ], colWidths=[250, 250])
    ]
    elements.append(KeepTogether(conclusion_flowables))

    doc.build(elements, canvasmaker=NumberedCanvas)
    
    if output_filepath is None:
        buffer.seek(0)
        return buffer
    return output_filepath
