#!/usr/bin/env python3
"""
Log Analyzer CLI - Interface de linha de comando para análise de logs
"""

import argparse
import sys
from log_analyzer.log_parser import LogAnalyzer
from log_analyzer.geoip import GeoIPDatabase
from log_analyzer.database import LogDatabase
from log_analyzer.export import CSVExporter, PDFExporter
from log_analyzer.graphics import GraphicsGenerator


def main():
    parser = argparse.ArgumentParser(
        description='Log Analyzer - Ferramenta de análise de logs de segurança',
        epilog='Exemplos:\n'
               '  python3 log_analyzer_cli.py --analyze --geoip --db\n'
               '  python3 log_analyzer_cli.py --export-csv logs.csv\n'
               '  python3 log_analyzer_cli.py --export-pdf report.pdf\n'
               '  python3 log_analyzer_cli.py --graphics all',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--analyze', action='store_true', 
                       help='Analisa SSH e HTTP logs')
    parser.add_argument('--geoip', action='store_true',
                       help='Realiza lookup GeoIP para IPs encontrados')
    parser.add_argument('--db', action='store_true',
                       help='Armazena dados em base de dados SQLite')
    parser.add_argument('--db-file', default='security_logs.db',
                       help='Caminho do ficheiro SQLite (padrão: security_logs.db)')
    parser.add_argument('--export-csv', metavar='FILE',
                       help='Exporta dados para CSV')
    parser.add_argument('--export-pdf', metavar='FILE',
                       help='Exporta relatório para PDF')
    parser.add_argument('--graphics', choices=['service', 'event', 'country', 'ip', 'pie', 'all'],
                       help='Gera gráficos')
    parser.add_argument('--stats', action='store_true',
                       help='Mostra estatísticas gerais')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Modo verboso')
    
    args = parser.parse_args()
    
    # Se nenhum argumento fornecido, mostrar ajuda
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Análise
    if args.analyze:
        print("[*] Analisando logs...")
        analyzer = LogAnalyzer()
        ssh_entries, http_entries = analyzer.analyze_all()
        
        print(f"[+] SSH: {len(ssh_entries)} entradas encontradas")
        print(f"[+] HTTP: {len(http_entries)} entradas encontradas")
        
        all_entries = ssh_entries + http_entries
        
        # GeoIP Lookup
        if args.geoip:
            print("[*] Realizando GeoIP lookup...")
            geoip = GeoIPDatabase()
            
            ips = set()
            for entry in all_entries:
                ips.add(entry.get('ip'))
            
            geo_data = geoip.batch_lookup(list(ips))
            
            # Adicionar informações de país aos entries
            for entry in all_entries:
                ip_info = geo_data.get(entry.get('ip'), {})
                entry['country_code'] = ip_info.get('country', 'XX')
                entry['country_name'] = ip_info.get('country_name', 'Unknown')
                
                if args.verbose:
                    print(f"  {entry.get('ip')} -> {entry.get('country_name')}")
        
        # Database
        if args.db:
            print(f"[*] Armazenando em base de dados: {args.db_file}")
            db = LogDatabase(args.db_file)
            
            count = db.insert_entries(all_entries)
            print(f"[+] {count} entradas inseridas na base de dados")
            
            # Atualizar estatísticas de IP
            for entry in all_entries:
                db.update_ip_statistics(
                    entry.get('ip'),
                    entry.get('country_code', 'XX'),
                    entry.get('country_name', 'Unknown'),
                    entry.get('event_type', '')
                )
        
        # Exportar CSV
        if args.export_csv:
            print(f"[*] Exportando para CSV: {args.export_csv}")
            CSVExporter.export_entries(all_entries, args.export_csv)
        
        # Exportar PDF
        if args.export_pdf or args.graphics:
            db = LogDatabase(args.db_file)
            stats = db.get_statistics()
            
            if args.export_pdf:
                print(f"[*] Gerando relatório PDF: {args.export_pdf}")
                PDFExporter.export_report(all_entries, stats, args.export_pdf)
            
            # Gráficos
            if args.graphics:
                print("[*] Gerando gráficos...")
                graphics_gen = GraphicsGenerator()
                top_ips = db.get_top_ips()
                top_countries = db.get_top_countries()
                
                if args.graphics in ['service', 'all']:
                    graphics_gen.plot_events_by_service(stats)
                    graphics_gen.plot_pie_services(stats)
                
                if args.graphics in ['event', 'all']:
                    graphics_gen.plot_events_by_type(stats)
                
                if args.graphics in ['country', 'all']:
                    graphics_gen.plot_top_countries(top_countries)
                
                if args.graphics in ['ip', 'all']:
                    graphics_gen.plot_top_ips(top_ips)
        
        # Estatísticas
        if args.stats:
            db = LogDatabase(args.db_file)
            stats = db.get_statistics()
            
            print("\n=== ESTATÍSTICAS GERAIS ===")
            print(f"Total de entradas: {stats['total_entries']}")
            print(f"IPs únicos: {stats['unique_ips']}")
            
            print("\nPor Serviço:")
            for service, count in stats['by_service'].items():
                print(f"  {service}: {count}")
            
            print("\nPor Tipo de Evento:")
            for event, count in stats['by_event'].items():
                print(f"  {event}: {count}")
    
    # Apenas estatísticas
    elif args.stats:
        db = LogDatabase(args.db_file)
        stats = db.get_statistics()
        
        print("\n=== ESTATÍSTICAS ===")
        print(f"Total de entradas: {stats['total_entries']}")
        print(f"IPs únicos: {stats['unique_ips']}")
        
        print("\nPor Serviço:")
        for service, count in stats['by_service'].items():
            print(f"  {service}: {count}")
        
        print("\nTop IPs:")
        top_ips = db.get_top_ips(5)
        for ip in top_ips:
            print(f"  {ip['ip_address']}: {ip['total_attempts']} tentativas ({ip['country_name']})")


if __name__ == '__main__':
    main()
