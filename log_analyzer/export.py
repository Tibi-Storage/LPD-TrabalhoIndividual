"""
Export Module - Exporta dados em CSV e PDF
"""

import csv
from typing import List, Dict
from datetime import datetime
from pathlib import Path


class CSVExporter:
    """Exporta dados para CSV"""
    
    @staticmethod
    def export_entries(entries: List[Dict], filename: str = None) -> str:
        """Exporta entradas para CSV"""
        
        if not filename:
            filename = f"log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if not entries:
            print("Nenhuma entrada para exportar")
            return filename
        
        # Obter todas as chaves dos dicionários
        fieldnames = set()
        for entry in entries:
            fieldnames.update(entry.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entries)
        
        print(f"Exportado para: {filename}")
        return filename
    
    @staticmethod
    def export_statistics(stats: Dict, filename: str = None) -> str:
        """Exporta estatísticas para CSV"""
        
        if not filename:
            filename = f"stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Estatísticas gerais
            writer.writerow(['Estatísticas Gerais'])
            writer.writerow(['Métrica', 'Valor'])
            for key, value in stats.get('general', {}).items():
                writer.writerow([key, value])
            
            writer.writerow([])
            writer.writerow(['Por Serviço'])
            writer.writerow(['Serviço', 'Contagem'])
            for service, count in stats.get('by_service', {}).items():
                writer.writerow([service, count])
            
            writer.writerow([])
            writer.writerow(['Por Evento'])
            writer.writerow(['Tipo de Evento', 'Contagem'])
            for event, count in stats.get('by_event', {}).items():
                writer.writerow([event, count])
            
            writer.writerow([])
            writer.writerow(['Top IPs'])
            writer.writerow(['IP', 'País', 'Total Tentativas', 'Falhadas', 'Bem-sucedidas'])
            for ip in stats.get('top_ips', []):
                writer.writerow([
                    ip.get('ip_address'),
                    ip.get('country_name'),
                    ip.get('total_attempts'),
                    ip.get('failed_attempts'),
                    ip.get('successful_attempts')
                ])
        
        print(f"Estatísticas exportadas para: {filename}")
        return filename


class PDFExporter:
    """Exporta relatórios para PDF usando reportlab"""
    
    @staticmethod
    def export_report(entries: List[Dict], stats: Dict, filename: str = None) -> str:
        """Exporta relatório de segurança em PDF"""
        
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            print("reportlab não instalado. Use: pip install reportlab")
            return None
        
        if not filename:
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Criar documento PDF
        doc = SimpleDocTemplate(filename, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        story.append(Paragraph("Relatório de Segurança - Análise de Logs", title_style))
        story.append(Paragraph(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Estatísticas Gerais
        story.append(Paragraph("Estatísticas Gerais", styles['Heading2']))
        
        general_data = [
            ['Métrica', 'Valor'],
            ['Total de Entradas', str(stats.get('total_entries', 0))],
            ['IPs Únicos', str(stats.get('unique_ips', 0))],
        ]
        
        general_table = Table(general_data, colWidths=[3*inch, 2*inch])
        general_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(general_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Por Serviço
        story.append(Paragraph("Tentativas por Serviço", styles['Heading2']))
        service_data = [['Serviço', 'Contagem']]
        for service, count in stats.get('by_service', {}).items():
            service_data.append([service, str(count)])
        
        service_table = Table(service_data, colWidths=[3*inch, 2*inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(service_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Top IPs (limitar a 10)
        if entries:
            story.append(PageBreak())
            story.append(Paragraph("Top IPs com Mais Tentativas", styles['Heading2']))
            
            top_ips = sorted(
                set((e.get('ip'), e.get('country_name', 'Unknown')) for e in entries[:100]),
                key=lambda x: x[0]
            )[:10]
            
            ip_data = [['IP Address', 'País']]
            for ip, country in top_ips:
                ip_data.append([ip, country or 'Unknown'])
            
            ip_table = Table(ip_data, colWidths=[3*inch, 2*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcyan),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(ip_table)
        
        # Construir PDF
        doc.build(story)
        print(f"Relatório gerado: {filename}")
        return filename
