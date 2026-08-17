import os
import io
from datetime import datetime
from flask import send_file

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from app.models.incident import Incident
from app.models.canary_file import CanaryFile
from app.models.quarantine_history import QuarantineHistory
from app.services.ai_service import AIService


def _generate_fallback_pdf(doc_title: str) -> io.BytesIO:
    """Generate minimal valid PDF stream if reportlab library is unavailable."""
    pdf_content = (
        "%PDF-1.4\n"
        "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n"
        "2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n"
        "3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R>> endobj\n"
        "4 0 obj <</Length 85>> stream\n"
        "BT /F1 12 Tf 50 700 Td (CanaryGuard Report: " + doc_title + ") Tj ET\n"
        "endstream\n"
        "endobj\n"
        "xref\n"
        "0 5\n"
        "0000000000 65535 f \n"
        "0000000009 00000 n \n"
        "0000000056 00000 n \n"
        "0000000127 00000 n \n"
        "0000000236 00000 n \n"
        "trailer <</Size 5 /Root 1 0 R>>\n"
        "startxref\n"
        "371\n"
        "%%EOF\n"
    )
    buf = io.BytesIO(pdf_content.encode('utf-8'))
    buf.seek(0)
    return buf


class PDFService:
    """
    Generates professional PDF AI Endpoint Threat Security Reports and Readiness Assessment Reports.
    """

    @classmethod
    def generate_security_report(cls):
        if not HAS_REPORTLAB:
            return _generate_fallback_pdf("Security Executive Report")

        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter

        buffer = io.BytesIO()

        def draw_header_footer(canvas, doc):
            canvas.saveState()
            # Header bar
            canvas.setFillColor(colors.HexColor('#0f172a'))
            canvas.rect(0, 700, 620, 150, fill=1, stroke=0)
            # Logo box - cyan rounded square
            canvas.setFillColor(colors.HexColor('#0284c7'))
            canvas.roundRect(20, 715, 55, 55, 8, fill=1, stroke=0)
            # CG text
            canvas.setFillColor(colors.HexColor('#ffffff'))
            canvas.setFont('Helvetica-Bold', 22)
            canvas.drawCentredString(47, 732, 'CG')
            # Yellow accent dot
            canvas.setFillColor(colors.HexColor('#fbbf24'))
            canvas.circle(62, 762, 5, fill=1, stroke=0)
            # Company name
            canvas.setFillColor(colors.HexColor('#ffffff'))
            canvas.setFont('Helvetica-Bold', 18)
            canvas.drawString(85, 745, 'CanaryGuard EDR')
            canvas.setFillColor(colors.HexColor('#0ea5e9'))
            canvas.setFont('Helvetica', 10)
            canvas.drawString(85, 728, 'AI Endpoint Detection & Response Platform')
            # Right side - report info
            canvas.setFillColor(colors.HexColor('#ffffff'))
            canvas.setFont('Helvetica-Bold', 11)
            canvas.drawRightString(590, 750, 'Security Executive Report')
            canvas.setFillColor(colors.HexColor('#94a3b8'))
            canvas.setFont('Helvetica', 9)
            canvas.drawRightString(590, 735, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}')
            # Green status badge
            canvas.setFillColor(colors.HexColor('#16a34a'))
            canvas.roundRect(510, 713, 80, 18, 4, fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor('#ffffff'))
            canvas.setFont('Helvetica-Bold', 8)
            canvas.drawCentredString(550, 718, 'PROTECTED')
            # Cyan accent line
            canvas.setFillColor(colors.HexColor('#0284c7'))
            canvas.rect(0, 698, 620, 3, fill=1, stroke=0)
            # Footer
            canvas.setFillColor(colors.HexColor('#f8fafc'))
            canvas.rect(0, 0, 620, 25, fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor('#64748b'))
            canvas.setFont('Helvetica', 7)
            canvas.drawString(20, 8, 'CanaryGuard EDR — Confidential Security Report')
            canvas.drawCentredString(306, 8, f'Page {doc.page}')
            canvas.drawRightString(590, 8, 'National Technical Research Organisation')
            canvas.restoreState()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=110,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        h2_style = ParagraphStyle(
            'SH2', parent=styles['Heading2'],
            fontName='Helvetica-Bold', fontSize=13, leading=16,
            textColor=colors.HexColor('#0f172a'), spaceBefore=14, spaceAfter=6
        )
        body_style = ParagraphStyle(
            'SBody', parent=styles['Normal'],
            fontName='Helvetica', fontSize=9, leading=13,
            textColor=colors.HexColor('#334155')
        )
        label_style = ParagraphStyle(
            'SLabel', parent=styles['Normal'],
            fontName='Helvetica-Bold', fontSize=9, leading=13,
            textColor=colors.HexColor('#64748b')
        )

        elements = []

        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        canaries_count = CanaryFile.query.filter_by(is_active=True).count()
        quarantine_count = QuarantineHistory.query.count()
        active_threats = sum(1 for i in incidents if i.status == 'ACTIVE')
        insights = AIService.get_dashboard_insights(True)

        # Threat trend banner
        trend = insights.get('threat_trend', 'NORMAL')
        if 'CRITICAL' in trend.upper():
            banner_color = '#dc2626'
            banner_icon = 'CRITICAL ELEVATION'
        elif 'ELEVATED' in trend.upper():
            banner_color = '#d97706'
            banner_icon = 'ELEVATED THREAT'
        else:
            banner_color = '#16a34a'
            banner_icon = 'NORMAL OPERATIONS'

        banner_data = [[Paragraph(
            f"<font color='#ffffff'><b>⚠ THREAT TREND: {banner_icon}</b></font>",
            ParagraphStyle('Banner', parent=styles['Normal'],
                fontName='Helvetica-Bold', fontSize=11, alignment=1))]]
        banner_table = Table(banner_data, colWidths=[540])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(banner_color)),
            ('PADDING', (0,0), (-1,-1), 10),
            ('ROUNDEDCORNERS', [6]),
        ]))
        elements.append(banner_table)
        elements.append(Spacer(1, 14))

        # 4-Column Metrics Table
        metrics_data = [
            [
                f"{len(incidents)}",
                f"{active_threats}",
                f"{canaries_count}",
                f"{quarantine_count}",
            ],
            [
                "Total Incidents",
                "Active Threats",
                "Active Canaries",
                "Quarantined",
            ]
        ]
        metrics_table = Table(metrics_data, colWidths=[132, 132, 132, 132])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#eff6ff')),
            ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#fef2f2')),
            ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#ecfeff')),
            ('BACKGROUND', (3,0), (3,-1), colors.HexColor('#f0fdf4')),
            ('BOX', (0,0), (0,-1), 2, colors.HexColor('#0284c7')),
            ('BOX', (1,0), (1,-1), 2, colors.HexColor('#dc2626')),
            ('BOX', (2,0), (2,-1), 2, colors.HexColor('#0ea5e9')),
            ('BOX', (3,0), (3,-1), 2, colors.HexColor('#16a34a')),
            ('TEXTCOLOR', (0,0), (0,0), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (1,0), (1,0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (2,0), (2,0), colors.HexColor('#0ea5e9')),
            ('TEXTCOLOR', (3,0), (3,0), colors.HexColor('#16a34a')),
            ('TEXTCOLOR', (0,1), (-1,1), colors.HexColor('#64748b')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 18),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,1), 9),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 12),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 18))

        # AI Telemetry section
        elements.append(HRFlowable(width='100%', thickness=3,
            color=colors.HexColor('#0284c7'), spaceAfter=8))
        elements.append(Paragraph('AI Security & Telemetry Summary', h2_style))

        telemetry_items = [
            ('✓ System Status', insights['monitoring_health'], '#16a34a'),
            ('⚡ Ransomware Status', insights['ransomware_status'], '#dc2626'),
            ('📁 Most Active Directory', insights['most_active_folder'], '#0284c7'),
            ('🎯 Most Targeted Extension', insights['most_targeted_type'], '#d97706'),
            ('📊 Highest Shannon Entropy', str(insights['highest_entropy_today']), '#7c3aed'),
            ('⬆ Threat Trend', insights['threat_trend'], '#dc2626'),
        ]

        tel_data = []
        for label, value, color in telemetry_items:
            tel_data.append([
                Paragraph(f"<b>{label}</b>", label_style),
                Paragraph(f"<font color='{color}'><b>{value}</b></font>", body_style)
            ])

        tel_table = Table(tel_data, colWidths=[200, 340])
        tel_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('ROWBACKGROUNDS', (0,0), (-1,-1),
                [colors.HexColor('#f8fafc'), colors.HexColor('#ffffff')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LINEAFTER', (0,0), (0,-1), 2, colors.HexColor('#0284c7')),
        ]))
        elements.append(tel_table)
        elements.append(Spacer(1, 18))

        # Incidents table
        elements.append(HRFlowable(width='100%', thickness=3,
            color=colors.HexColor('#0284c7'), spaceAfter=8))
        elements.append(Paragraph('Recent Critical Incident Telemetry', h2_style))

        def threat_color(level):
            return {'CRITICAL':'#dc2626','HIGH':'#d97706',
                    'MEDIUM':'#ca8a04','LOW':'#16a34a'}.get(
                    str(level).upper(), '#64748b')

        def score_color(score):
            s = int(score.replace('%','')) if isinstance(score,str) else int(score)
            if s >= 70: return '#dc2626'
            if s >= 40: return '#d97706'
            return '#16a34a'

        inc_data = [['ID','Timestamp','File','Threat','Entropy','Process','Score']]
        for inc in incidents[:10]:
            score = int(inc.confidence_score) if inc.confidence_score else AIService.calculate_threat_score({
                'canary_triggered': inc.canary_triggered,
                'entropy_value': inc.entropy_value,
                'process_name': inc.process_name,
                'description': inc.description
            })
            ts = inc.created_at.strftime('%d %b %H:%M') if inc.created_at else 'N/A'
            fname = os.path.basename(inc.file_path or 'N/A')
            tc = threat_color(inc.threat_level)
            inc_data.append([
                Paragraph(f"<b>#{inc.id}</b>", body_style),
                Paragraph(ts, body_style),
                Paragraph(fname, body_style),
                Paragraph(f"<font color='{tc}'><b>{inc.threat_level}</b></font>", body_style),
                Paragraph(f"{inc.entropy_value:.2f}" if inc.entropy_value else 'N/A', body_style),
                Paragraph(inc.process_name or 'Unknown', body_style),
                Paragraph(f"<font color='{score_color(score)}'><b>{score}%</b></font>", body_style),
            ])

        if len(inc_data) == 1:
            inc_data.append([Paragraph('No incidents recorded', body_style),
                '-','-','-','-','-','-'])

        inc_table = Table(inc_data, colWidths=[35, 72, 130, 65, 50, 110, 48])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
                [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 7),
            ('ALIGN', (4,0), (6,-1), 'CENTER'),
        ]))
        elements.append(inc_table)
        elements.append(Spacer(1, 18))
        elements.append(PageBreak())

        # Recommendations page
        elements.append(HRFlowable(width='100%', thickness=3,
            color=colors.HexColor('#0284c7'), spaceAfter=8))
        elements.append(Paragraph('Recovery Status & Recommendations', h2_style))

        latest_inc = incidents[0] if incidents else None
        if latest_inc and hasattr(latest_inc, 'get_recovery_checklist'):
            chk = latest_inc.get_recovery_checklist()
            chk_items = [
                ('Threat Contained', chk.get('Threat contained', False)),
                ('Backup Availability Verified', chk.get('Backup availability verified', False)),
                ('RTO/RPO Readiness Confirmed', chk.get('Recovery point identified', False)),
                ('Restoration Verified', chk.get('Restoration verified', False)),
            ]
            chk_data = []
            for item_label, done in chk_items:
                color = '#16a34a' if done else '#dc2626'
                icon = '✓' if done else '✗'
                chk_data.append([
                    Paragraph(f"<font color='{color}'><b>{icon}</b></font>",
                        ParagraphStyle('CIcon', parent=styles['Normal'],
                        fontSize=14, alignment=1)),
                    Paragraph(f"<b>{item_label}</b>",
                        ParagraphStyle('CItem', parent=styles['Normal'],
                        fontSize=10, textColor=colors.HexColor('#0f172a'))),
                    Paragraph(
                        "<font color='#16a34a'>Complete</font>" if done
                        else "<font color='#dc2626'>Pending</font>",
                        ParagraphStyle('CStat', parent=styles['Normal'],
                        fontSize=9, alignment=1)),
                ])
            chk_table = Table(chk_data, colWidths=[40, 380, 120])
            chk_table.setStyle(TableStyle([
                ('ROWBACKGROUNDS', (0,0), (-1,-1),
                    [colors.HexColor('#f0fdf4'), colors.HexColor('#ffffff')]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 10),
                ('ALIGN', (0,0), (0,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(chk_table)
            elements.append(Spacer(1, 16))

        recs = [
            ('Canary Deployment', 'Maintain automated canary decoy files in all high-value network shares to detect ransomware instantly.'),
            ('Auto Quarantine', 'Keep Auto Quarantine enabled to terminate suspicious elevated PIDs before mass encryption occurs.'),
            ('Isolated Backups', 'Configure air-gapped or immutable WORM backups to ensure clean restore points are always available.'),
            ('RTO/RPO Targets', 'Define and verify RTO/RPO targets. Run quarterly restore drills into sandbox environments.'),
            ('Recovery Playbooks', 'Document and test recovery playbooks with all stakeholders including legal, PR, and C-suite.'),
        ]

        for i, (title, desc) in enumerate(recs):
            rec_data = [[
                Paragraph(f"<font color='#ffffff'><b>{i+1}</b></font>",
                    ParagraphStyle('RNum', parent=styles['Normal'],
                    fontSize=14, alignment=1, fontName='Helvetica-Bold')),
                Paragraph(f"<b>{title}</b><br/><font size=9 color='#334155'>{desc}</font>",
                    ParagraphStyle('RText', parent=styles['Normal'],
                    fontSize=10, leading=14))
            ]]
            rec_table = Table(rec_data, colWidths=[36, 504])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), colors.HexColor('#0284c7')),
                ('BACKGROUND', (1,0), (1,0), colors.HexColor('#eff6ff')),
                ('LINEAFTER', (0,0), (0,0), 2, colors.HexColor('#0284c7')),
                ('LINEBEFORE', (1,0), (1,0), 3, colors.HexColor('#0284c7')),
                ('PADDING', (0,0), (0,0), 10),
                ('PADDING', (1,0), (1,0), 12),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ROUNDEDCORNERS', [6]),
            ]))
            elements.append(rec_table)
            elements.append(Spacer(1, 8))

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width='100%', thickness=1,
            color=colors.HexColor('#e2e8f0'), spaceAfter=8))
        elements.append(Paragraph(
            "CanaryGuard EDR Security Platform — Confidential Automated Forensic Report — SIH260074",
            ParagraphStyle('Footer2', parent=styles['Normal'],
            fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=1)))

        doc.build(elements,
            onFirstPage=draw_header_footer,
            onLaterPages=draw_header_footer)
        buffer.seek(0)
        return buffer

    @classmethod
    def generate_readiness_report(cls, assessment_id: int):
        """
        Generates a 5-page executive Ransomware Readiness Assessment PDF Report with enhanced ReportLab visual elements.
        """
        if not HAS_REPORTLAB:
            return _generate_fallback_pdf(f"Readiness Assessment #{assessment_id}")

        from app.services.assessment_service import AssessmentService
        from app.configuration.assessment_controls import ASSESSMENT_CONTROLS
        from reportlab.graphics.shapes import Drawing, Rect, String, Group

        breakdown = AssessmentService.get_score_breakdown(assessment_id)

        buffer = io.BytesIO()

        # Canvas callbacks for page numbering
        def draw_page_number(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor('#64748b'))
            canvas.drawString(36, 20, f"Page {doc.page} — CanaryGuard Confidential")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Typography & Paragraph Styles
        title_cover = ParagraphStyle(
            'CoverTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=colors.HexColor('#0f172a'),
            alignment=1
        )
        subtitle_cover = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#64748b'),
            alignment=1
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=10,
            spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=10,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'BodyTextCustom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        body_bold = ParagraphStyle(
            'BodyBoldCustom',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        overall_score = float(breakdown.get('overall_score', 0.0))
        maturity_level = breakdown.get('maturity_level', 'Initial')
        org_name = breakdown.get('org_name', 'Organization')
        assessor_name = breakdown.get('assessor_name', 'System Admin')
        created_at_str = breakdown.get('created_at', '')[:10] if breakdown.get('created_at') else datetime.now().strftime('%Y-%m-%d')

        # Determine Score Theme Colors
        if overall_score > 70.0:
            score_bg_color = colors.HexColor('#16a34a')
            score_shadow_color = colors.HexColor('#15803d')
        elif overall_score >= 40.0:
            score_bg_color = colors.HexColor('#d97706')
            score_shadow_color = colors.HexColor('#b45309')
        else:
            score_bg_color = colors.HexColor('#dc2626')
            score_shadow_color = colors.HexColor('#b91c1c')

        # Helper function to add a section heading followed by a thin cyan HR rule
        def add_section_heading(text, style=h1_style):
            elements.append(Paragraph(text, style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0284c7'), spaceAfter=10, spaceBefore=4))

        # =====================================================================
        # PAGE 1 — COVER PAGE
        # =====================================================================
        # 1. Full-width dark banner (#0f172a) with "CANARYGUARD EDR" in white bold 28pt & cyan (#0284c7) subtitle bar
        banner_drawing = Drawing(540, 75)
        # Dark top banner rect
        banner_drawing.add(Rect(0, 20, 540, 55, fillColor=colors.HexColor('#0f172a'), strokeColor=None))
        banner_drawing.add(String(20, 36, "CANARYGUARD EDR", fontName="Helvetica-Bold", fontSize=28, fillColor=colors.white))
        # Subtitle text inside dark banner right aligned
        banner_drawing.add(String(340, 38, "Ransomware Posture Assessment Framework", fontName="Helvetica", fontSize=9, fillColor=colors.HexColor('#cbd5e1')))
        # Cyan subtitle bar below it
        banner_drawing.add(Rect(0, 0, 540, 20, fillColor=colors.HexColor('#0284c7'), strokeColor=None))
        banner_drawing.add(String(20, 5, f"Executive Audit Report | Ref: #RS-{assessment_id:04d}", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.white))

        elements.append(banner_drawing)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Ransomware Readiness Assessment Report", title_cover))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("Enterprise Security Posture & NIST CSF Framework Audit", subtitle_cover))
        elements.append(Spacer(1, 20))

        # Organization Details Table
        meta_table_data = [
            [Paragraph("<b>Organization Name:</b>", body_style), Paragraph(org_name, body_bold)],
            [Paragraph("<b>Organization Size:</b>", body_style), Paragraph(str(breakdown.get('org_size', 'N/A')).capitalize(), body_style)],
            [Paragraph("<b>Industry Sector:</b>", body_style), Paragraph(str(breakdown.get('industry', 'N/A')), body_style)],
            [Paragraph("<b>Lead Assessor:</b>", body_style), Paragraph(assessor_name, body_style)],
            [Paragraph("<b>Audit Completed Date:</b>", body_style), Paragraph(created_at_str, body_style)],
        ]
        meta_table = Table(meta_table_data, colWidths=[180, 360])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 20))

        # Colored rectangle behind the score using reportlab's Drawing/Rect with 4pt rounded corners and shadow offset 3pt
        score_drawing = Drawing(540, 110)
        # Shadow rectangle offset by 3pt (down 3pt, right 3pt)
        score_drawing.add(Rect(143, 7, 260, 95, rx=4, ry=4, fillColor=score_shadow_color, strokeColor=None))
        # Main Score box with 4pt rounded corners
        score_drawing.add(Rect(140, 10, 260, 95, rx=4, ry=4, fillColor=score_bg_color, strokeColor=None))
        # Score number in white bold 48pt
        score_drawing.add(String(270, 52, f"{overall_score:.1f}%", fontName="Helvetica-Bold", fontSize=48, fillColor=colors.white, textAnchor="middle"))
        # Maturity Level label inside box
        score_drawing.add(String(270, 22, f"NIST Maturity Tier: {maturity_level}", fontName="Helvetica-Bold", fontSize=12, fillColor=colors.white, textAnchor="middle"))

        elements.append(score_drawing)
        elements.append(Spacer(1, 20))

        # 3-column summary bar below score showing: "32 Controls Audited | 6 Domains | NIST CSF 2.0" each in its own shaded box
        summary_bar_data = [
            [
                Paragraph("<b>32 Controls Audited</b>", ParagraphStyle('SumAlign1', parent=body_bold, alignment=1)),
                Paragraph("<b>6 Domains</b>", ParagraphStyle('SumAlign2', parent=body_bold, alignment=1)),
                Paragraph("<b>NIST CSF 2.0</b>", ParagraphStyle('SumAlign3', parent=body_bold, alignment=1))
            ]
        ]
        summary_bar_table = Table(summary_bar_data, colWidths=[175, 175, 175])
        summary_bar_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor('#f1f5f9')),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (2,0), (2,0), colors.HexColor('#cbd5e1')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 1, colors.white),
            ('PADDING', (0,0), (-1,-1), 10),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(summary_bar_table)

        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
        elements.append(Paragraph("CanaryGuard EDR Platform — Confidential Security Posture Evaluation", subtitle_cover))
        elements.append(PageBreak())

        # =====================================================================
        # PAGE 2 — EXECUTIVE SUMMARY
        # =====================================================================
        add_section_heading("Executive Summary & Risk Narrative", h1_style)

        # Compute Domain Statistics
        domains = breakdown.get('domains', [])
        sorted_domains = sorted(domains, key=lambda d: d.get('score', 0.0))
        weakest_dom = sorted_domains[0] if sorted_domains else {'domain_name': 'N/A', 'score': 0.0}
        strongest_dom = sorted_domains[-1] if sorted_domains else {'domain_name': 'N/A', 'score': 0.0}

        gap_count = 0
        total_controls = 0
        auto_detected_count = 0
        for d in domains:
            for c in d.get('controls', []):
                total_controls += 1
                if c.get('score_value', 0.0) < 80.0:
                    gap_count += 1
                if c.get('auto_detected'):
                    auto_detected_count += 1

        narrative_text = (
            f"This Ransomware Readiness Assessment report presents the technical posture evaluation for <b>{org_name}</b>. "
            f"The organization achieved an Overall Maturity Score of <b>{overall_score:.1f}%</b>, corresponding to a NIST Cybersecurity Maturity Tier of <b>'{maturity_level}'</b>. "
            f"Analysis across the 6 core security domains identified <b>'{strongest_dom['domain_name']}'</b> as the strongest domain ({strongest_dom['score']:.1f}%) and "
            f"<b>'{weakest_dom['domain_name']}'</b> as requiring the most immediate remediation attention ({weakest_dom['score']:.1f}%). "
            f"Out of <b>{total_controls}</b> controls audited, a total of <b>{gap_count}</b> security controls were identified with gaps below the recommended implementation benchmark."
        )

        # Colored left border accent to the narrative paragraph using a thin colored Rectangle beside it
        narrative_p = Paragraph(narrative_text, body_style)
        narrative_table = Table([[narrative_p]], colWidths=[530])
        narrative_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor('#f8fafc')),
            ('LINELEFT', (0,0), (0,0), 4, colors.HexColor('#0284c7')), # Left accent bar
            ('PADDING', (0,0), (0,0), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(narrative_table)
        elements.append(Spacer(1, 15))

        # "Gaps at a Glance" mini summary box with 3 stats in colored boxes: Total Controls | Gaps Found | Auto-Detected
        add_section_heading("Gaps at a Glance", h2_style)
        gaps_summary_data = [
            [
                Paragraph(f"<b>Total Controls Audited</b><br/><font size=14 color='#0f172a'><b>{total_controls}</b></font>", ParagraphStyle('G1', parent=body_style, alignment=1)),
                Paragraph(f"<b>Gaps Found</b><br/><font size=14 color='#dc2626'><b>{gap_count}</b></font>", ParagraphStyle('G2', parent=body_style, alignment=1)),
                Paragraph(f"<b>Auto-Detected</b><br/><font size=14 color='#0284c7'><b>{auto_detected_count}</b></font>", ParagraphStyle('G3', parent=body_style, alignment=1))
            ]
        ]
        gaps_summary_table = Table(gaps_summary_data, colWidths=[175, 175, 175])
        gaps_summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#fee2e2')),
            ('BACKGROUND', (2,0), (2,0), colors.HexColor('#e0f2fe')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 1, colors.white),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ]))
        elements.append(gaps_summary_table)
        elements.append(Spacer(1, 15))

        add_section_heading("Domain Framework Score Summary", h2_style)

        domain_table_data = [["Domain Code & Name", "Weighted Score", "Maturity Tier", "Posture Status"]]
        domain_table_styles = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('ALIGN', (1,0), (2,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 8), # Increased padding to 8pt minimum
        ]

        row_idx = 1
        for d in domains:
            d_score = float(d.get('score', 0.0))
            if d_score >= 80.0:
                status_str = "<font color='#16a34a'><b>OPTIMAL (OK)</b></font>"
                row_bg = colors.HexColor('#dcfce7') # Green (#dcfce7) if >=80
            elif d_score >= 40.0:
                status_str = "<font color='#d97706'><b>PARTIAL (GAP)</b></font>"
                row_bg = colors.HexColor('#fef3c7') # Amber (#fef3c7) if >=40
            else:
                status_str = "<font color='#dc2626'><b>CRITICAL (GAP)</b></font>"
                row_bg = colors.HexColor('#fee2e2') # Red (#fee2e2) if <40

            tier_str = AssessmentService.get_maturity_level(d_score)
            domain_table_data.append([
                Paragraph(f"<b>{d['domain_code']}</b> — {d['domain_name']}", body_style),
                f"{d_score:.1f}%",
                tier_str,
                Paragraph(status_str, body_style)
            ])

            domain_table_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), row_bg))
            row_idx += 1

        domain_table = Table(domain_table_data, colWidths=[220, 90, 90, 130])
        domain_table.setStyle(TableStyle(domain_table_styles))
        elements.append(domain_table)
        elements.append(PageBreak())

        # =====================================================================
        # PAGE 3 — DOMAIN DETAIL
        # =====================================================================
        add_section_heading("Domain Framework Controls Detail", h1_style)

        for d in domains:
            d_score = float(d.get('score', 0.0))
            
            # Each domain section gets a colored header bar (full width Rectangle in #1e293b) with domain name in white
            dom_header_drawing = Drawing(530, 24)
            dom_header_drawing.add(Rect(0, 0, 530, 24, fillColor=colors.HexColor('#1e293b'), strokeColor=None))
            dom_header_text = f"{d['domain_code']} — {d['domain_name']}  (Score: {d_score:.1f}%)"
            dom_header_drawing.add(String(10, 7, dom_header_text, fontName="Helvetica-Bold", fontSize=10, fillColor=colors.white))
            elements.append(dom_header_drawing)
            elements.append(Spacer(1, 4))

            ctrl_table_data = [["Code", "Control Title", "Maturity Answer", "Status", "Detection Notes"]]
            ctrl_table_styles = [
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('ALIGN', (2,0), (2,-1), 'CENTER'),
                ('ALIGN', (3,0), (3,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 8), # Increased padding to 8pt minimum
            ]

            c_row_idx = 1
            for c in d.get('controls', []):
                ans = c.get('maturity_answer', 'not_implemented')
                ans_str = ans.replace('_', ' ').title()
                score_val = float(c.get('score_value', 0.0))

                # Status column: replace text indicators with colored background cells — green cell for ✓, amber for ⚠, red for ✗
                if score_val >= 80.0:
                    status_cell = Paragraph("<b>✓</b>", ParagraphStyle('StatOk', parent=body_style, alignment=1, textColor=colors.HexColor('#15803d')))
                    status_cell_bg = colors.HexColor('#dcfce7')
                elif score_val >= 40.0:
                    status_cell = Paragraph("<b>⚠</b>", ParagraphStyle('StatWarn', parent=body_style, alignment=1, textColor=colors.HexColor('#b45309')))
                    status_cell_bg = colors.HexColor('#fef3c7')
                else:
                    status_cell = Paragraph("<b>✗</b>", ParagraphStyle('StatErr', parent=body_style, alignment=1, textColor=colors.HexColor('#b91c1c')))
                    status_cell_bg = colors.HexColor('#fee2e2')

                is_auto = c.get('auto_detected')
                auto_str = "(Auto-detected by CanaryGuard)" if is_auto else "Manual Assessment"

                ctrl_table_data.append([
                    c['control_code'],
                    Paragraph(f"<b>{c['control_title']}</b>", body_style),
                    ans_str,
                    status_cell,
                    Paragraph(f"<font size=7.5 color='#64748b'>{auto_str}</font>", body_style)
                ])

                # Auto-detected rows get a light cyan (#e0f2fe) row background
                if is_auto:
                    ctrl_table_styles.append(('BACKGROUND', (0, c_row_idx), (-1, c_row_idx), colors.HexColor('#e0f2fe')))
                else:
                    ctrl_table_styles.append(('BACKGROUND', (0, c_row_idx), (-1, c_row_idx), colors.white if c_row_idx % 2 == 1 else colors.HexColor('#f8fafc')))

                # Apply specific background to Status column cell
                ctrl_table_styles.append(('BACKGROUND', (3, c_row_idx), (3, c_row_idx), status_cell_bg))
                c_row_idx += 1

            ctrl_table = Table(ctrl_table_data, colWidths=[80, 185, 95, 45, 125])
            ctrl_table.setStyle(TableStyle(ctrl_table_styles))
            elements.append(ctrl_table)
            elements.append(Spacer(1, 10))

        elements.append(PageBreak())

        # =====================================================================
        # PAGE 4 — PRIORITIZED REMEDIATION ROADMAP
        # =====================================================================
        add_section_heading("Prioritized Remediation Roadmap", h1_style)

        control_weight_map = {c['control_code']: c.get('weight', 1) for c in ASSESSMENT_CONTROLS}

        # Gather all gaps
        critical_gaps = []
        high_gaps = []
        medium_gaps = []

        for d in domains:
            for c in d.get('controls', []):
                if float(c.get('score_value', 0.0)) < 80.0:
                    w = control_weight_map.get(c['control_code'], 1)
                    item = {
                        'code': c['control_code'],
                        'title': c['control_title'],
                        'answer': c['maturity_answer'].replace('_', ' ').title(),
                        'tip': c.get('remediation_tip', 'Implement control to meet security baseline.')
                    }
                    if w == 3:
                        critical_gaps.append(item)
                    elif w == 2:
                        high_gaps.append(item)
                    else:
                        medium_gaps.append(item)

        def render_gap_group(group_title, gap_list, header_bg, badge_text, badge_bg, border_hex):
            group_elements = []
            
            # Colored section header bar with white text
            header_drawing = Drawing(530, 24)
            header_drawing.add(Rect(0, 0, 530, 24, fillColor=header_bg, strokeColor=None))
            header_text = f"{group_title} ({len(gap_list)} Items)"
            header_drawing.add(String(10, 7, header_text, fontName="Helvetica-Bold", fontSize=10, fillColor=colors.white))
            group_elements.append(header_drawing)
            group_elements.append(Spacer(1, 4))

            if not gap_list:
                group_elements.append(Paragraph("<i>No gaps identified in this priority tier.</i>", body_style))
                group_elements.append(Spacer(1, 10))
                return group_elements

            tbl_data = [["Priority", "Control", "Current State", "Recommended Remediation Action"]]
            tbl_styles = [
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('ALIGN', (0,0), (0,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor(border_hex)),
                ('PADDING', (0,0), (-1,-1), 8), # Increased padding to 8pt minimum
            ]

            r_idx = 1
            for g in gap_list:
                # Add priority badge column showing "🔴 CRITICAL", "🟡 HIGH", "🔵 MEDIUM" as colored Paragraph cells
                badge_p = Paragraph(f"<b>{badge_text}</b>", ParagraphStyle('BadgeStyle', parent=body_style, alignment=1, fontSize=7.5, textColor=colors.white))

                tbl_data.append([
                    badge_p,
                    Paragraph(f"<b>{g['title']}</b><br/><font size=7.5 color='#64748b'>{g['code']}</font>", body_style),
                    g['answer'],
                    Paragraph(g['tip'], body_style)
                ])

                tbl_styles.append(('BACKGROUND', (0, r_idx), (0, r_idx), badge_bg))
                tbl_styles.append(('BACKGROUND', (1, r_idx), (-1, r_idx), colors.white if r_idx % 2 == 1 else colors.HexColor('#f8fafc')))
                r_idx += 1

            tbl = Table(tbl_data, colWidths=[80, 140, 80, 230])
            tbl.setStyle(TableStyle(tbl_styles))
            group_elements.append(tbl)
            group_elements.append(Spacer(1, 12))
            return group_elements

        # Critical section header bar: red background (#dc2626) white text
        for el in render_gap_group("Critical Priority (Weight 3 — Immediate Containment Required)", critical_gaps, colors.HexColor('#dc2626'), "🔴 CRITICAL", colors.HexColor('#dc2626'), '#fca5a5'):
            elements.append(el)

        # High section header bar: amber background (#d97706) white text
        for el in render_gap_group("High Priority (Weight 2 — 30-Day Remediation Schedule)", high_gaps, colors.HexColor('#d97706'), "🟡 HIGH", colors.HexColor('#d97706'), '#fde68a'):
            elements.append(el)

        # Medium section header bar: blue background (#0284c7) white text
        for el in render_gap_group("Medium Priority (Weight 1 — 90-Day Defense Hardening)", medium_gaps, colors.HexColor('#0284c7'), "🔵 MEDIUM", colors.HexColor('#0284c7'), '#cbd5e1'):
            elements.append(el)

        elements.append(PageBreak())

        # =====================================================================
        # PAGE 5 — ABOUT CANARYGUARD & METHODOLOGY
        # =====================================================================
        add_section_heading("About CanaryGuard EDR & Audit Methodology", h1_style)

        elements.append(Paragraph("CanaryGuard Endpoint Detection & Response (EDR) Architecture", h2_style))
        about_text = (
            "CanaryGuard is an enterprise-grade Endpoint Detection & Response (EDR) platform designed specifically "
            "to catch ransomware attacks through behavioral analysis rather than signature matching. The system deploys "
            "hidden decoy canary files across monitored file shares, monitors real-time filesystem events via low-overhead "
            "kernel hooks, calculates Shannon Entropy to identify payload encryption, and automatically isolates malicious process trees."
        )
        elements.append(Paragraph(about_text, body_style))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("NIST Cybersecurity Framework (CSF 2.0) Audit Basis", h2_style))
        methodology_text = (
            "This assessment framework is modeled after the NIST Cybersecurity Framework (CSF 2.0) and CIS Critical Security Controls (v8). "
            "The 6 core domains (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, and PEOPLE) are weighted based on empirical ransomware incident response data. "
            "Maturity levels range from Tier 1 (Initial — 0-20%), Tier 2 (Developing — 21-40%), Tier 3 (Defined — 41-60%), "
            "Tier 4 (Managed — 61-80%), to Tier 5 (Optimized — 81-100%). Controls marked as Auto-Detected are validated dynamically "
            "against CanaryGuard's active operational agent telemetry."
        )

        # Styled info box around the methodology text with a light blue (#eff6ff) background and blue left border
        methodology_p = Paragraph(methodology_text, body_style)
        info_box_table = Table([[methodology_p]], colWidths=[530])
        info_box_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor('#eff6ff')), # Light blue background (#eff6ff)
            ('LINELEFT', (0,0), (0,0), 4, colors.HexColor('#0284c7')), # Blue left border
            ('PADDING', (0,0), (0,0), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(info_box_table)
        elements.append(Spacer(1, 20))



        # Professional sign-off table with the CanaryGuard logo text "CG" in a cyan square box beside the signature
        logo_box_drawing = Drawing(40, 40)
        logo_box_drawing.add(Rect(0, 0, 40, 40, rx=4, ry=4, fillColor=colors.HexColor('#0284c7'), strokeColor=None))
        logo_box_drawing.add(String(20, 12, "CG", fontName="Helvetica-Bold", fontSize=18, fillColor=colors.white, textAnchor="middle"))

        sign_off_data = [
            [
                logo_box_drawing,
                Paragraph("<b>Report Generated By:</b><br/>CanaryGuard EDR Assessment Engine", body_style),
                Paragraph(f"<b>Report Signature:</b><br/>SHA-256 Verified Audit #{assessment_id:04d}", body_style)
            ]
        ]
        sign_off_table = Table(sign_off_data, colWidths=[50, 230, 250])
        sign_off_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (0,0), 'CENTER'),
        ]))
        elements.append(sign_off_table)

        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
        elements.append(Paragraph("CanaryGuard EDR Security Platform — Confidential Automated Forensic Report", subtitle_cover))

        doc.build(elements, onFirstPage=draw_page_number, onLaterPages=draw_page_number)
        buffer.seek(0)
        return buffer

