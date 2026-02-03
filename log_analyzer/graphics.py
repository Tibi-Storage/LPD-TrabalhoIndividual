"""
Graphics Module - Gera gráficos com matplotlib
"""

from typing import List, Dict
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


class GraphicsGenerator:
    """Gera gráficos de análise de logs"""
    
    @staticmethod
    def plot_events_by_service(stats: Dict, filename: str = None):
        """Gráfico de eventos por serviço"""
        
        if not filename:
            filename = f"chart_service_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        services = list(stats.get('by_service', {}).keys())
        counts = list(stats.get('by_service', {}).values())
        
        if not services:
            print("Sem dados para gráfico")
            return
        
        plt.figure(figsize=(10, 6))
        plt.bar(services, counts, color='steelblue', edgecolor='navy', alpha=0.7)
        plt.title('Tentativas de Acesso por Serviço', fontsize=14, fontweight='bold')
        plt.xlabel('Serviço', fontsize=12)
        plt.ylabel('Número de Tentativas', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Gráfico salvo: {filename}")
        return filename
    
    @staticmethod
    def plot_events_by_type(stats: Dict, filename: str = None):
        """Gráfico de eventos por tipo"""
        
        if not filename:
            filename = f"chart_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        events = list(stats.get('by_event', {}).keys())
        counts = list(stats.get('by_event', {}).values())
        
        if not events:
            print("Sem dados para gráfico")
            return
        
        colors = ['#ff6b6b' if 'Failed' in event else '#51cf66' for event in events]
        
        plt.figure(figsize=(10, 6))
        plt.bar(events, counts, color=colors, edgecolor='black', alpha=0.7)
        plt.title('Tentativas por Tipo de Evento', fontsize=14, fontweight='bold')
        plt.xlabel('Tipo de Evento', fontsize=12)
        plt.ylabel('Número de Tentativas', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Gráfico salvo: {filename}")
        return filename
    
    @staticmethod
    def plot_top_countries(top_countries: List[Dict], filename: str = None):
        """Gráfico dos países com mais tentativas"""
        
        if not filename:
            filename = f"chart_countries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        if not top_countries:
            print("Sem dados para gráfico")
            return
        
        countries = [c['country_name'] for c in top_countries[:10]]
        counts = [c.get('count', 0) for c in top_countries[:10]]
        failed = [c.get('failed', 0) for c in top_countries[:10]]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        x = range(len(countries))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], counts, width, label='Total', color='steelblue', alpha=0.8)
        ax.bar([i + width/2 for i in x], failed, width, label='Falhadas', color='crimson', alpha=0.8)
        
        ax.set_xlabel('País', fontsize=12)
        ax.set_ylabel('Número de Tentativas', fontsize=12)
        ax.set_title('Top 10 Países com Mais Tentativas', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(countries, rotation=45, ha='right')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Gráfico salvo: {filename}")
        return filename
    
    @staticmethod
    def plot_top_ips(top_ips: List[Dict], filename: str = None):
        """Gráfico dos IPs com mais tentativas"""
        
        if not filename:
            filename = f"chart_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        if not top_ips:
            print("Sem dados para gráfico")
            return
        
        ips = [ip['ip_address'][:15] for ip in top_ips[:10]]  # Limitar comprimento
        attempts = [ip.get('total_attempts', 0) for ip in top_ips[:10]]
        failed = [ip.get('failed_attempts', 0) for ip in top_ips[:10]]
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        x = range(len(ips))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], attempts, width, label='Total', color='steelblue', alpha=0.8)
        ax.bar([i + width/2 for i in x], failed, width, label='Falhadas', color='crimson', alpha=0.8)
        
        ax.set_xlabel('IP Address', fontsize=12)
        ax.set_ylabel('Número de Tentativas', fontsize=12)
        ax.set_title('Top 10 IPs com Mais Tentativas', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45, ha='right')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Gráfico salvo: {filename}")
        return filename
    
    @staticmethod
    def plot_pie_services(stats: Dict, filename: str = None):
        """Gráfico tipo pizza para distribuição de serviços"""
        
        if not filename:
            filename = f"chart_pie_services_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        services = list(stats.get('by_service', {}).keys())
        counts = list(stats.get('by_service', {}).values())
        
        if not services:
            print("Sem dados para gráfico")
            return
        
        plt.figure(figsize=(10, 8))
        colors_pie = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc']
        plt.pie(counts, labels=services, autopct='%1.1f%%', colors=colors_pie[:len(services)],
                startangle=90, textprops={'fontsize': 11})
        plt.title('Distribuição de Tentativas por Serviço', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Gráfico salvo: {filename}")
        return filename
