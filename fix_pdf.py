import re

with open('app/services/pdf_service.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the metrics table section
old = content[content.find('metrics_data = [['):content.find('elements.append(metrics_table)\n        elements.append(Spacer(1, 18))') + len('elements.append(metrics_table)\n        elements.append(Spacer(1, 18))')]

new = '''metrics_data = [[
            f"{len(incidents)}",
            f"{active_threats}",
            f"{canaries_count}",
            f"{quarantine_count}",
        ],[
            "Total Incidents",
            "Active Threats", 
            "Active Canaries",
            "Quarantined",
        ]]
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
            ('FONTSIZE', (0,0), (-1,0), 22),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,1), 9),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 12),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 18))'''

content = content.replace(old, new)

with open('app/services/pdf_service.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('Done!')