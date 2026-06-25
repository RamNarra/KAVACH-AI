"""
report_generator.py — Kavach AI PDF Report Generator

Creates a professional, branded incident report PDF using ReportLab Platypus.
Includes a cover page, vector gauge chart, summary blocks, and formatted tables.
"""

import os
import datetime
from math import cos, sin, radians
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image
from reportlab.graphics.shapes import Drawing, Wedge, Line, Polygon, String as DString, Circle, Rect
from reportlab.pdfgen import canvas

# ----------------------------------------------------------------------
# Numbered Canvas for "Page X of Y" and Custom Header/Footer
# ----------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        # Capture page state for the second-pass page numbers
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            if self._pageNumber > 1: # Suppress header/footer on cover page
                self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, total_pages: int):
        self.saveState()
        
        # Retrieve APK Hash from document template
        apk_hash = "N/A"
        if hasattr(self, '_doctemplate') and self._doctemplate and hasattr(self._doctemplate, 'apk_hash'):
            apk_hash = self._doctemplate.apk_hash
            
        # Draw Header
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0F172A"))
        self.drawString(54, 750, f"KAVACH AI — INCIDENT REPORT | SHA-256: {apk_hash}")
        
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(558, 750, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        # Header line
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)
        
        # Draw Footer
        self.line(54, 50, 558, 50)
        self.drawString(54, 38, "CONFIDENTIAL — BANK OF INDIA SECURITY DIVISION")
        self.drawRightString(558, 38, f"Page {self._pageNumber} of {total_pages}")
        
        self.restoreState()

# ----------------------------------------------------------------------
# Helper: Draw Vector Gauge Chart
# ----------------------------------------------------------------------
def draw_risk_gauge(score: int) -> Drawing:
    """Draws a vector semi-circular gauge chart representing the risk score."""
    d = Drawing(200, 110)
    
    # Background semi-circle slots (Green, Yellow, Red) using Wedge
    # Green Sector (Low risk: 0-39 score -> 110 to 180 deg)
    d.add(Wedge(100, 15, 80, 110, 180, fillColor=colors.HexColor("#10B981"), strokeColor=None))
    # Yellow Sector (Medium risk: 40-74 score -> 45 to 110 deg)
    d.add(Wedge(100, 15, 80, 45, 110, fillColor=colors.HexColor("#F59E0B"), strokeColor=None))
    # Red Sector (High risk: 75-100 score -> 0 to 45 deg)
    d.add(Wedge(100, 15, 80, 0, 45, fillColor=colors.HexColor("#EF4444"), strokeColor=None))
    
    # Overlay a smaller white circle to hollow out the wedges and create a ring
    d.add(Circle(100, 15, 62, fillColor=colors.white, strokeColor=None))
    
    # Draw needle center pin
    d.add(Circle(100, 15, 6, fillColor=colors.HexColor("#1E293B"), strokeColor=colors.HexColor("#0F172A")))
    
    # Calculate needle direction angle based on score
    # Score 0 -> Angle 180 degrees (Left)
    # Score 100 -> Angle 0 degrees (Right)
    angle = 180.0 - (float(score) * 1.8)
    rad = radians(angle)
    
    needle_length = 65
    dx = needle_length * cos(rad)
    dy = needle_length * sin(rad)
    
    # Draw needle line
    d.add(Line(100, 15, 100 + dx, 15 + dy, strokeColor=colors.HexColor("#0F172A"), strokeWidth=3.5))
    
    # Draw score text badge below needle center
    d.add(DString(100, 28, f"{score}/100", fontName="Helvetica-Bold", fontSize=14, textAnchor="middle", fillColor=colors.HexColor("#1E293B")))
    
    # Add simple risk category string
    if score >= 75:
        verdict_str = "CRITICAL THREAT"
        verdict_color = colors.HexColor("#EF4444")
    elif score >= 40:
        verdict_str = "SUSPICIOUS PROFILE"
        verdict_color = colors.HexColor("#F59E0B")
    else:
        verdict_str = "LOW RISK"
        verdict_color = colors.HexColor("#10B981")
        
    d.add(DString(100, 45, verdict_str, fontName="Helvetica-Bold", fontSize=9, textAnchor="middle", fillColor=verdict_color))
    return d

# ----------------------------------------------------------------------
# PDF Generation Core
# ----------------------------------------------------------------------
def generate_pdf_report(scan_data: Dict[str, Any], output_path: str):
    """
    Constructs the Platypus document story and writes it out to output_path.
    """
    # Initialize Document with letter size and 0.75 in margins
    margin = 54 # 0.75 inch in points
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin + 18,
        bottomMargin=margin
    )
    
    # Store APK hash in document instance for header access
    doc.apk_hash = scan_data.get("apk_hash", "N/A")
    
    styles = getSampleStyleSheet()
    
    # Custom Brand Palette Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569"),
        spaceAfter=24
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8
    )
    
    code_style = ParagraphStyle(
        'ReportCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F8F9FA"),
        borderColor=colors.HexColor("#E2E8F0"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=8
    )

    story = []
    
    # ------------------------------------------------------------------
    # COVER PAGE
    # ------------------------------------------------------------------
    story.append(Spacer(1, 40))
    
    # Draw Cover Header Accent Line
    # Table wrapping logo details
    right_align_style = ParagraphStyle(
        'RightAlign',
        parent=styles['Normal'],
        alignment=2 # Right align
    )
    logo_data = [
        [
            Paragraph("<b>KAVACH AI</b><br/><font size=7 color='#64748B'>NEXT-GEN FRAUD DETECTOR</font>", styles['Normal']),
            Paragraph("<b>BANK OF INDIA</b><br/><font size=7 color='#64748B'>SECURITY DIVISION</font>", right_align_style)
        ]
    ]
    logo_table = Table(logo_data, colWidths=[250, 254])
    logo_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(logo_table)
    
    # Horizontal accent divider
    story.append(Table([[""]], colWidths=[504], rowHeights=[2], style=TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#2563EB")),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ])))
    story.append(Spacer(1, 100))
    
    story.append(Paragraph("MALWARE INVESTIGATION REPORT", title_style))
    story.append(Paragraph(
        "Automated Static & Dynamic Forensic Audit of Suspicious Android Application package (APK). Prepared for security incident response teams.",
        subtitle_style
    ))
    
    story.append(Spacer(1, 40))
    
    # Metadata Table
    verdict = scan_data.get("threat_level", "UNKNOWN").upper()
    score = scan_data.get("risk_score", 0)
    verdict_badge_color = "#EF4444" if verdict in ("CRITICAL", "HIGH") else ("#F59E0B" if verdict == "MEDIUM" else "#10B981")
    
    metadata_rows = [
        [Paragraph("<b>Target File:</b>", body_style), Paragraph(scan_data.get("filename", "unknown.apk"), body_style)],
        [Paragraph("<b>Package Name:</b>", body_style), Paragraph(scan_data.get("package_name", "N/A"), body_style)],
        [Paragraph("<b>SHA-256 Hash:</b>", body_style), Paragraph(scan_data.get("apk_hash", "N/A"), body_style)],
        [Paragraph("<b>Generated Time:</b>", body_style), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)],
        [Paragraph("<b>Threat Classification:</b>", body_style), Paragraph(f"<font color='{verdict_badge_color}'><b>{verdict} THREAT ({score}/100)</b></font>", body_style)],
    ]
    meta_table = Table(metadata_rows, colWidths=[150, 354])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8F9FA")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)
    
    story.append(PageBreak())
    
    # ------------------------------------------------------------------
    # SECTION 1: EXECUTIVE SUMMARY & DASHBOARD
    # ------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & Incident Dashboard", h1_style))
    story.append(Spacer(1, 8))
    
    # 2-Column layout: Dashboard Gauge on Left, Threat Briefing on Right
    dashboard_briefing_table_data = [
        [
            draw_risk_gauge(score),
            [
                Paragraph("<b>Threat Summary Brief</b>", h2_style),
                Paragraph(
                    scan_data.get("investigation_report", {}).get("summary") or 
                    scan_data.get("static_analysis", {}).get("investigation_report", {}).get("summary") or
                    "No summary available. Check static engine logs for details.",
                    body_style
                )
            ]
        ]
    ]
    db_brief_table = Table(dashboard_briefing_table_data, colWidths=[200, 304])
    db_brief_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('RIGHTPADDING', (0,0), (0,0), 10),
        ('LEFTPADDING', (1,0), (1,0), 10),
    ]))
    story.append(db_brief_table)
    story.append(Spacer(1, 14))
    
    # Dynamic summaries from banking alerts & CISO briefs
    story.append(Paragraph("<b>Bank Agent Operational Alert</b>", h2_style))
    story.append(Paragraph(
        scan_data.get("investigation_report", {}).get("bank_agent_alert") or 
        scan_data.get("static_analysis", {}).get("investigation_report", {}).get("bank_agent_alert") or 
        "This application displays indicators of high risk. Verify permission access vectors.",
        body_style
    ))
    
    story.append(Paragraph("<b>Regulatory Risk Briefing (CISO)</b>", h2_style))
    story.append(Paragraph(
        scan_data.get("investigation_report", {}).get("ciso_brief") or 
        scan_data.get("static_analysis", {}).get("investigation_report", {}).get("ciso_brief") or 
        "Audit logs suggest compliance risk under standard RBI Digital Banking security guidelines.",
        body_style
    ))
    
    # ------------------------------------------------------------------
    # SECTION 2: TECHNICAL THREAT DETECTIONS
    # ------------------------------------------------------------------
    story.append(Paragraph("2. Static & Behavioral Detections", h1_style))
    
    # Rules / Banking Fraud Badges Table
    banking_fraud_data = scan_data.get("banking_fraud", {})
    badges = banking_fraud_data.get("badges", [])
    
    story.append(Paragraph("<b>Core Rules and Fraud Indicators Triggered</b>", h2_style))
    if not badges:
        story.append(Paragraph("No rule violations triggered.", body_style))
    else:
        badge_headers = [
            Paragraph("<b>Rule / Title</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>Details</b>", body_style)
        ]
        badge_rows = [badge_headers]
        for b in badges:
            sev = b.get("severity", "MEDIUM").upper()
            scolor = "#EF4444" if sev == "CRITICAL" else ("#F59E0B" if sev == "HIGH" else "#3B82F6")
            badge_rows.append([
                Paragraph(f"<b>{b.get('title', 'Unknown')}</b>", body_style),
                Paragraph(f"<font color='{scolor}'><b>{sev}</b></font>", body_style),
                Paragraph(b.get("summary", ""), body_style)
            ])
            
        badge_table = Table(badge_rows, colWidths=[150, 70, 284])
        badge_table_style = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#E2E8F0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]
        
        # Alternating row colors
        for idx in range(1, len(badge_rows)):
            bg = "#F8F9FA" if idx % 2 == 1 else "#FFFFFF"
            badge_table_style.append(('BACKGROUND', (0, idx), (-1, idx), colors.HexColor(bg)))
            
        badge_table.setStyle(TableStyle(badge_table_style))
        story.append(badge_table)
        
    story.append(Spacer(1, 10))
    
    # ML Prediction Feature Verdict
    ml_class = scan_data.get("ml_classification") or scan_data.get("static_analysis", {}).get("ml_classification")
    if ml_class and ml_class.get("status") == "SUCCESS":
        story.append(Paragraph("<b>Machine Learning Hybrid Vector Verification</b>", h2_style))
        is_mal = ml_class.get("is_malicious", False)
        ml_color = "#EF4444" if is_mal else "#10B981"
        ml_verdict = "MALICIOUS" if is_mal else "BENIGN"
        story.append(Paragraph(
            f"The DREBIN-trained Random Forest model evaluated 545 static permissions, API sequences, and layout targets. "
            f"Verdict: <font color='{ml_color}'><b>{ml_verdict}</b></font> with <b>{int(ml_class.get('ml_confidence_score', 0.0)*100)}% confidence</b>. "
            f"Model matched <b>{ml_class.get('matching_features_count', 0)}</b> suspect feature footprints.",
            body_style
        ))
        story.append(Spacer(1, 10))

    # Certificate & Signing Forensics
    cert_info = scan_data.get("evidence", {}).get("certificate_info") or scan_data.get("static_analysis", {}).get("evidence", {}).get("certificate_info")
    if cert_info:
        story.append(Paragraph("<b>Certificate & Signing Forensics</b>", h2_style))
        is_signed = cert_info.get("is_signed", False)
        verdict = cert_info.get("verdict", "UNKNOWN_SELF_SIGNED_DEVELOPER")
        verdict_desc = cert_info.get("verdict_description", "No certificate analysis available.")
        
        verdict_color = "#10B981" if verdict == "LEGIT_MATCHED_SIGNER" else ("#EF4444" if verdict in ("MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE", "UNSIGNED") else "#F59E0B")
        
        cert_status_text = f"<font color='{verdict_color}'><b>{verdict.replace('_', ' ')}</b></font> - {verdict_desc}"
        story.append(Paragraph(f"<b>Verification Verdict:</b> {cert_status_text}", body_style))
        story.append(Spacer(1, 6))
        
        if is_signed:
            cert_rows = [
                [Paragraph("<b>Subject:</b>", body_style), Paragraph(cert_info.get("subject", "N/A"), body_style)],
                [Paragraph("<b>Issuer:</b>", body_style), Paragraph(cert_info.get("issuer", "N/A"), body_style)],
                [Paragraph("<b>SHA-256 Fingerprint:</b>", body_style), Paragraph(cert_info.get("sha256", "N/A"), body_style)],
                [Paragraph("<b>Validity Window:</b>", body_style), Paragraph(f"{cert_info.get('valid_from', 'N/A')} to {cert_info.get('valid_to', 'N/A')}", body_style)],
                [Paragraph("<b>Signature Scheme / Algo:</b>", body_style), Paragraph(f"{cert_info.get('signature_scheme', 'N/A')} ({cert_info.get('signature_algo', 'N/A')})", body_style)],
            ]
            cert_table = Table(cert_rows, colWidths=[130, 374])
            cert_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F1F5F9")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(cert_table)
        else:
            story.append(Paragraph("No cryptographic signing certificates found in the APK.", body_style))
            
        story.append(Spacer(1, 10))

    # Sandbox Evasion & Camouflage Telemetry
    evasion = scan_data.get("evidence", {}).get("dynamic_analysis", {}).get("evasion_report") or scan_data.get("evasion_report")
    if evasion and evasion.get("evasion_detected"):
        story.append(Paragraph("<b>Sandbox Evasion & Camouflage Telemetry</b>", h2_style))
        story.append(Paragraph(
            f"During dynamic execution inside our isolated sandbox, the application actively attempted to detect the virtualized analysis environment "
            f"or analysis hooks. Kavach AI's dynamic camouflage hooks automatically spoofed system APIs and bypassed these stalls to guarantee trace continuity. "
            f"This evasion attempt triggers a strict <b>+20 risk score penalty</b>.",
            body_style
        ))
        
        highlights = evasion.get("evidence_highlights", [])
        if highlights:
            ev_list = []
            for h in highlights:
                ev_list.append(f"• {h}")
            story.append(Paragraph("<br/>".join(ev_list), body_style))
        story.append(Spacer(1, 10))

    # ─── SECTION 2.5: Sandbox Dynamic Behavior Trace Evidence ───
    doc_id = scan_data.get("id")
    dyn_analysis = scan_data.get("evidence", {}).get("dynamic_analysis", {})
    if dyn_analysis and dyn_analysis.get("status") in ("COMPLETED", "PARTIAL"):
        story.append(Paragraph("<b>Sandbox Dynamic Behavior Trace Evidence</b>", h2_style))
        
        duration = dyn_analysis.get("duration_seconds", 120)
        events_count = dyn_analysis.get("event_count", 0)
        story.append(Paragraph(
            f"Kavach AI executed the target application inside a sandboxed Android environment for {duration} seconds. "
            f"An automated 14-step user movement playbook simulated real-world device usage. "
            f"In total, <b>{events_count}</b> low-level API instrumentation hooks and events were captured.",
            body_style
        ))
        story.append(Spacer(1, 6))

        # Hooked Runtime API Anomalies Table
        runtime_findings = dyn_analysis.get("runtime_findings", [])
        if runtime_findings:
            story.append(Paragraph("<b>Hooked Runtime API Anomalies</b>", h2_style))
            finding_rows = [[
                Paragraph("<b>Anomaly / Call Signature</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Forensic Evidence / Summary</b>", body_style)
            ]]
            for rf in runtime_findings:
                sev = rf.get("severity", "LOW")
                sev_color = "#EF4444" if sev in ("CRITICAL", "HIGH") else "#F59E0B"
                finding_rows.append([
                    Paragraph(rf.get("title", "Anomaly"), body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
                    Paragraph(rf.get("summary", "No details available."), body_style)
                ])
            
            rf_table = Table(finding_rows, colWidths=[150, 60, 294])
            rf_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F8FAFC")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(rf_table)
            story.append(Spacer(1, 10))

        # Keyframe Screenshots
        import glob
        _BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
        SCAN_TEMP_DIR = os.environ.get("SCAN_TEMP_DIR", os.path.join(_BACKEND_DIR, "tmp_scans"))
        screenshots_dir = os.path.join(SCAN_TEMP_DIR, "screenshots", doc_id)
        screenshot_files = sorted(glob.glob(os.path.join(screenshots_dir, "*.png")))
        
        if screenshot_files:
            story.append(Paragraph("<b>Captured Execution Keyframes</b>", h2_style))
            story.append(Paragraph(
                "Below are key timeline frames captured from the emulator screen during automated playbook execution:",
                body_style
            ))
            story.append(Spacer(1, 6))
            
            selected_files = []
            if len(screenshot_files) == 1:
                selected_files = [screenshot_files[0]]
            elif len(screenshot_files) == 2:
                selected_files = [screenshot_files[0], screenshot_files[-1]]
            else:
                selected_files = [
                    screenshot_files[0],
                    screenshot_files[len(screenshot_files) // 2],
                    screenshot_files[-1]
                ]
            
            import re
            img_row = []
            caption_row = []
            for i, fpath in enumerate(selected_files):
                try:
                    img_flow = Image(fpath, width=120, height=213)  # Aspect ratio 9:16 scaled down
                    img_row.append(img_flow)
                    
                    # Extract elapsed time from filename (e.g. frame_001_12s.png -> 12s)
                    basename = os.path.basename(fpath)
                    match = re.search(r'_(\d+)s\.png$', basename)
                    elapsed_str = f"t = {match.group(1)}s" if match else ""
                    
                    label = "Start of Trace" if i == 0 else ("End of Trace" if i == len(selected_files) - 1 else "Mid-run Trace")
                    caption_label = f"Frame {i+1} ({elapsed_str})" if elapsed_str else f"Frame {i+1}"
                    caption_row.append(Paragraph(f"<font size=8><b>{caption_label}:</b> {label}</font>", body_style))
                except Exception as img_err:
                    logger.error(f"Error loading screenshot for PDF: {img_err}")
            
            if img_row:
                # Pad rows to 3 items if fewer to maintain column alignment
                while len(img_row) < 3:
                    img_row.append("")
                    caption_row.append("")
                
                img_table = Table([img_row, caption_row], colWidths=[168, 168, 168])
                img_table.setStyle(TableStyle([
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ]))
                story.append(img_table)
                story.append(Spacer(1, 10))

        # Reference to full video
        if dyn_analysis.get("has_video") or dyn_analysis.get("video_path"):
            story.append(Paragraph(
                f"<b>Full Recording Proof:</b> A full video screen recording of this dynamic analysis session has been "
                f"archived on the Kavach AI server. Security analysts can play back or download this recording in the "
                f"dashboard or via the secure API endpoint: <code>/api/analysis/{doc_id}/dynamic/video</code>.",
                body_style
            ))
            story.append(Spacer(1, 10))
        
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # SECTION 3: CODE AUTOPSY (PHASE 2 ENGINE)
    # ------------------------------------------------------------------
    autopsy = scan_data.get("code_autopsy") or {}
    class_results = autopsy.get("class_results", [])
    
    if class_results:
        story.append(Paragraph("3. AI Code Autopsy (Reverse Engineering Report)", h1_style))
        story.append(Paragraph(
            "The Code Autopsy Engine reverse engineered decompiled Java classes and located specific suspicious methods matching fraud signatures:",
            body_style
        ))
        
        for idx, res in enumerate(class_results): # Show all flagged classes
            class_name = res.get("class_name", "Unknown Class")
            story.append(Paragraph(f"<b>Class: {class_name}</b>", h2_style))
            story.append(Paragraph(f"<b>Malicious Action:</b> {res.get('malicious_action', 'N/A')}", body_style))
            
            # Draw code snippets with explanation
            dang_lines = res.get("dangerous_lines", [])
            if dang_lines:
                snippet_lines = []
                explanations = []
                for line in dang_lines:
                    line_num = line.get("line_number", "?")
                    code_str = line.get("code_snippet", "")
                    stripped_code = code_str.lstrip()
                    indent_spaces = len(code_str) - len(stripped_code)
                    indent_html = "&nbsp;" * indent_spaces
                    
                    expl = line.get("threat_action", "")
                    snippet_lines.append(f"Line {line_num}: {indent_html}{stripped_code}")
                    explanations.append(f"• <b>Line {line_num}:</b> {expl}")
                
                snippet_text = "<br/>".join(snippet_lines)
                story.append(Paragraph("<b>flagged code snippet:</b>", body_style))
                story.append(Paragraph(snippet_text, code_style))
                story.append(Paragraph("<br/>".join(explanations), body_style))
                story.append(Spacer(1, 10))
                
        story.append(Spacer(1, 10))
        
    # ------------------------------------------------------------------
    # SECTION 4: MITRE MOBILE ATT&CK MAPPING
    # ------------------------------------------------------------------
    mitre_techs = scan_data.get("attack_techniques", [])
    if mitre_techs:
        story.append(Paragraph("4. MITRE Mobile ATT&CK Mapping", h1_style))
        story.append(Paragraph(
            "Heuristic evidence and permissions triggered matching tactics inside the MITRE ATT&CK Mobile matrix:",
            body_style
        ))
        story.append(Spacer(1, 6))
        
        mitre_rows = [[
            Paragraph("<b>ID</b>", body_style),
            Paragraph("<b>Technique Name</b>", body_style),
            Paragraph("<b>Tactic</b>", body_style),
            Paragraph("<b>Evidence Details</b>", body_style)
        ]]
        
        for tech in mitre_techs: # Show all techniques
            sources_text = "<br/>".join([
                f"• {s.get('source')}: {s.get('detail')}" for s in tech.get("sources", [])
            ])
            mitre_rows.append([
                Paragraph(tech.get("id", ""), body_style),
                Paragraph(tech.get("name", ""), body_style),
                Paragraph(tech.get("tactic", ""), body_style),
                Paragraph(sources_text, body_style)
            ])
            
        m_table = Table(mitre_rows, colWidths=[65, 120, 95, 224])
        m_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#F8FAFC"), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(m_table)
        story.append(Spacer(1, 14))

    # ------------------------------------------------------------------
    # SECTION 5: C2 THREAT INFRASTRUCTURE APPENDIX
    # ------------------------------------------------------------------
    c2_indicators = scan_data.get("c2_indicators", [])
    if c2_indicators:
        story.append(Paragraph("5. Command & Control (C2) Infrastructure Appendix", h1_style))
        story.append(Paragraph(
            "The following network nodes and Command & Control indicators were extracted statically/dynamically and enriched:",
            body_style
        ))
        story.append(Spacer(1, 6))
        
        c2_rows = [[
            Paragraph("<b>Indicator</b>", body_style),
            Paragraph("<b>Type</b>", body_style),
            Paragraph("<b>Geolocation</b>", body_style),
            Paragraph("<b>Network (ASN)</b>", body_style),
            Paragraph("<b>Reputation</b>", body_style)
        ]]
        
        for c2 in c2_indicators: # Show all C2 servers
            rep_score = c2.get("reputation", 0)
            rep_color = "#EF4444" if rep_score > 50 else "#10B981"
            c2_rows.append([
                Paragraph(f"<b>{c2.get('id', '')}</b>", body_style),
                Paragraph(c2.get("indicator_type", "domain").upper(), body_style),
                Paragraph(c2.get("geolocation", "Unknown"), body_style),
                Paragraph(c2.get("asn", "Unknown"), body_style),
                Paragraph(f"<font color='{rep_color}'><b>{rep_score}%</b></font>", body_style)
            ])
            
        c2_table = Table(c2_rows, colWidths=[130, 50, 114, 150, 60])
        c2_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#F8FAFC"), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(c2_table)
        story.append(Spacer(1, 14))

    # ------------------------------------------------------------------
    # SECTION 6: RECOMMENDED ACTION MITIGATIONS
    # ------------------------------------------------------------------
    story.append(Paragraph("6. Recommended Mitigation Actions", h1_style))
    story.append(Paragraph(
        "Based on the threat score and observed behaviors, the Bank Security Operations Center (SOC) should execute the following playbooks immediately:",
        body_style
    ))
    
    playbook_data = [
        [Paragraph("<b>Risk Tier</b>", body_style), Paragraph("<b>Action Item</b>", body_style), Paragraph("<b>Responsible Party</b>", body_style)],
        [
            Paragraph("Critical / High (Score >= 75)", body_style),
            Paragraph("1. Add package name & hash to MDM blacklist.<br/>2. Trigger customer app session termination.<br/>3. Revoke active net-banking API tokens.", body_style),
            Paragraph("SOC Security Team", body_style)
        ],
        [
            Paragraph("Medium (Score 40-74)", body_style),
            Paragraph("1. Flag account for transaction limits monitoring.<br/>2. Send warning SMS notifying customer of suspicious apps.", body_style),
            Paragraph("Fraud Operations", body_style)
        ],
        [
            Paragraph("Low (Score < 40)", body_style),
            Paragraph("1. Standard scan log ingestion.<br/>2. Allow execution with baseline telemetry.", body_style),
            Paragraph("Automated Pipeline", body_style)
        ],
    ]
    p_table = Table(playbook_data, colWidths=[130, 250, 124])
    p_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(p_table)
    
    # Build Document Story
    doc.build(story, canvasmaker=NumberedCanvas)
