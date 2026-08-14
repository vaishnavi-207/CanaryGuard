import os
import io
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from app.models.incident import Incident
from app.models.canary_file import CanaryFile
from app.models.quarantine_history import QuarantineHistory
from app.services.ai_service import AIService
from datetime import datetime

class PDFService:
    """
    Generates professional PDF AI Endpoint Threat Security Reports.
    """

    @classmethod
    def generate_security_report(cls):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a')
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748b')
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyDark',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        bold_body = ParagraphStyle(
            'BoldBody',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header Title Table
        header_data = [
            [
                Paragraph("<b>CANARYGUARD EDR</b><br/><font size=9 color='#64748b'>AI Endpoint Detection & Response</font>", title_style),
                Paragraph(f"<b>Security Executive Report</b><br/>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>Status: <b>PROTECTED</b>", subtitle_style)
            ]
        ]
        header_table = Table(header_data, colWidths=[300, 240])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=15))

        # Overall Metrics Summary Table
        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        canaries_count = CanaryFile.query.filter_by(is_active=True).count()
        quarantine_count = QuarantineHistory.query.count()
        active_threats = sum(1 for i in incidents if i.status == 'ACTIVE')

        insights = AIService.get_dashboard_insights(True)

        metrics_data = [
            [
                Paragraph(f"<b>Total Incidents</b><br/><font size=14 color='#0f172a'><b>{len(incidents)}</b></font>", body_style),
                Paragraph(f"<b>Active Threats</b><br/><font size=14 color='#dc2626'><b>{active_threats}</b></font>", body_style),
                Paragraph(f"<b>Active Canaries</b><br/><font size=14 color='#0284c7'><b>{canaries_count}</b></font>", body_style),
                Paragraph(f"<b>Quarantined</b><br/><font size=14 color='#16a34a'><b>{quarantine_count}</b></font>", body_style),
            ]
        ]
        metrics_table = Table(metrics_data, colWidths=[135, 135, 135, 135])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 10),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 15))

        # AI Threat Insights Section
        elements.append(Paragraph("AI Security & Telemetry Summary", h2_style))
        ai_summary_text = (
            f"<b>System Monitoring Status:</b> {insights['monitoring_health']}<br/>"
            f"<b>Ransomware Threat Status:</b> {insights['ransomware_status']}<br/>"
            f"<b>Most Active Directory:</b> {insights['most_active_folder']}<br/>"
            f"<b>Most Targeted Extension:</b> {insights['most_targeted_type']}<br/>"
            f"<b>Highest Recorded Shannon Entropy:</b> {insights['highest_entropy_today']}<br/>"
            f"<b>Threat Trend Assessment:</b> <b>{insights['threat_trend']}</b>"
        )
        elements.append(Paragraph(ai_summary_text, body_style))
        elements.append(Spacer(1, 15))

        # Recent Incidents Table & AI Analysis
        elements.append(Paragraph("Recent Critical Incident Telemetry", h2_style))
        
        inc_table_data = [["ID", "Timestamp", "File Path", "Threat Level", "Entropy", "Process", "Score"]]
        for inc in incidents[:10]:
            score = int(inc.confidence_score) if inc.confidence_score else AIService.calculate_threat_score({
                'canary_triggered': inc.canary_triggered,
                'entropy_value': inc.entropy_value,
                'process_name': inc.process_name,
                'description': inc.description
            })
            time_str = inc.created_at.strftime("%Y-%m-%d %H:%M") if hasattr(inc, 'created_at') and inc.created_at else "N/A"
            filename = os.path.basename(inc.file_path or 'N/A')
            inc_table_data.append([
                str(inc.id),
                time_str,
                filename,
                inc.threat_level,
                f"{inc.entropy_value:.2f}" if inc.entropy_value else "N/A",
                inc.process_name or "Unknown",
                f"{score}%"
            ])

        if len(inc_table_data) == 1:
            inc_table_data.append(["-", "No incidents recorded", "-", "-", "-", "-", "-"])

        inc_table = Table(inc_table_data, colWidths=[30, 95, 150, 70, 50, 95, 50])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(inc_table)
        elements.append(Spacer(1, 15))

        # Security Recommendations
        elements.append(Paragraph("AI Security Recommendations", h2_style))
        recs = [
            "1. Maintain automated canary decoy files in all high-value network shares.",
            "2. Keep Auto Quarantine enabled to instantly terminate suspicious elevated PIDs.",
            "3. Enforce offline backup routines for protected directories.",
            "4. Review processes exhibiting high file entropy (> 7.0 Shannon scale)."
        ]
        for r in recs:
            elements.append(Paragraph(f"• {r}", body_style))

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
        elements.append(Paragraph("CanaryGuard EDR Security Platform — Confidential Automated Forensic Report", subtitle_style))

        doc.build(elements)
        buffer.seek(0)
        return buffer
