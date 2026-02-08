import argparse
import sys
import time
import os

# --- IMPORTAR OS TEUS MÓDULOS ---
# Certifica-te que estes ficheiros estão na mesma pasta
from SynScan import syn_scan
from SynFlood import syn_flood
from UdpFlood import udp_flood
from port_knocking import execute_knocking, check_ssh_status
from log_analyzer_cli import analyze_logs_logic, gerar_relatorio_texto

# --- FUNÇÕES DE AUXÍLIO ---
def print_callback(msg):
    """Callback simples para imprimir no terminal em vez da GUI"""
    print(msg)

def banner():
    print(r"""
    _   _      _                      _    _____           _     
   | \ | |    | |                    | |  |_   _|         | |    
   |  \| | ___| |___      _____  _ __| | __ | | ___   ___| |___ 
   | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / | |/ _ \ / _ \ / __|
   | |\  |  __/ |_ \ V  V / (_) | |  |   <  | | (_) | (_) | \__ \
   |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ \_/\___/ \___/|_|___/
                                CLI v1.0
    """)

# --- FUNÇÕES PRINCIPAIS DO CLI ---

def handle_scan(args):
    print(f"\n[*] A iniciar SYN Scan em {args.ip}...")
    print(f"[*] Portas: {args.ports}")
    
    try:
        # Converter string "22,80" para lista [22, 80]
        port_list = [int(p.strip()) for p in args.ports.split(",")]
        
        start_time = time.time()
        open_ports = syn_scan(args.ip, port_list, callback=print_callback)
        duration = time.time() - start_time
        
        print("\n" + "-"*40)
        print(f"RESUMO DO SCAN ({duration:.2f}s)")
        print("-"*40)
        if open_ports:
            print(f"SUCESSO: Foram encontradas {len(open_ports)} portas abertas:")
            for p in open_ports:
                print(f"  [+] Porta {p}/TCP ABERTA")
        else:
            print("Nenhuma porta aberta encontrada.")
            
    except Exception as e:
        print(f"[ERRO] Falha no scan: {e}")

def handle_flood(args):
    print(f"\n[*] A iniciar ataque {args.type.upper()} Flood...")
    print(f"[*] Alvo: {args.ip}:{args.port}")
    print(f"[*] Pacotes: {args.count}")
    print("-" * 40)
    
    try:
        if args.type == "syn":
            sent = syn_flood(args.ip, args.port, args.count, callback=print_callback)
        else:
            sent = udp_flood(args.ip, args.port, args.count, callback=print_callback)
            
        print(f"\n[CONCLUÍDO] Total de pacotes enviados: {sent}")
        
    except KeyboardInterrupt:
        print("\n[!] Ataque interrompido pelo utilizador.")
    except Exception as e:
        print(f"\n[ERRO] {e}")

def handle_knock(args):
    print(f"\n[*] A iniciar Port Knocking em {args.ip}...")
    
    try:
        seq = [int(p.strip()) for p in args.sequence.split(",")]
        print(f"[*] Sequência: {seq}")
        print(f"[*] Verificando SSH na porta {args.ssh_port}...")
        
        if check_ssh_status(args.ip, args.ssh_port):
            print("[!] AVISO: A porta SSH já está aberta!")
            return

        print("[+] SSH Fechado. Executar sequência de batidas...")
        execute_knocking(args.ip, seq, callback=print_callback)
        
        print("[*] Aguardando 2 segundos para atualização da firewall...")
        time.sleep(2)
        
        if check_ssh_status(args.ip, args.ssh_port):
            print("\n[SUCESSO] O Port Knocking funcionou! Porta SSH ABERTA.")
        else:
            print("\n[FALHA] A porta SSH continua fechada. Verifique a sequência.")
            
    except Exception as e:
        print(f"[ERRO] {e}")

def handle_logs(args):
    print(f"\n[*] A iniciar Análise Forense de Logs...")
    
    # Usa a lógica importada do log_analyzer_cli (sem duplicar código!)
    success = analyze_logs_logic(args.ssh, args.ufw, callback=print_callback)
    
    if success:
        # Se a análise correu bem, imprime o relatório de texto
        # (Função importada também)
        gerar_relatorio_texto()

# --- MAIN ---
def main():
    banner()
    
    parser = argparse.ArgumentParser(description="Network Tools Suite - Modo CLI")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")

    # 1. SCAN
    scan_parser = subparsers.add_parser("scan", help="Varrimento de Portas SYN")
    scan_parser.add_argument("ip", help="IP Alvo")
    scan_parser.add_argument("-p", "--ports", default="22,80,443,3306,8080", help="Lista de portas (ex: 22,80)")

    # 2. SYN FLOOD
    syn_parser = subparsers.add_parser("synflood", help="Ataque DoS SYN Flood")
    syn_parser.add_argument("ip", help="IP Alvo")
    syn_parser.add_argument("port", type=int, help="Porta Alvo")
    syn_parser.add_argument("-c", "--count", type=int, default=1000, help="Quantidade de pacotes")
    syn_parser.set_defaults(type="syn")

    # 3. UDP FLOOD
    udp_parser = subparsers.add_parser("udpflood", help="Ataque DoS UDP Flood")
    udp_parser.add_argument("ip", help="IP Alvo")
    udp_parser.add_argument("port", type=int, help="Porta Alvo")
    udp_parser.add_argument("-c", "--count", type=int, default=1000, help="Quantidade de pacotes")
    udp_parser.set_defaults(type="udp")

    # 4. PORT KNOCKING
    knock_parser = subparsers.add_parser("knock", help="Cliente Port Knocking")
    knock_parser.add_argument("ip", help="IP Alvo")
    knock_parser.add_argument("-s", "--sequence", required=True, help="Sequência de portas (ex: 7000,8000,9000)")
    knock_parser.add_argument("--ssh-port", type=int, default=22, help="Porta SSH para verificar")

    # 5. LOG ANALYZER
    log_parser = subparsers.add_parser("logs", help="Analisador de Logs Forense")
    log_parser.add_argument("--ssh", default="auth.log", help="Caminho do log SSH")
    log_parser.add_argument("--ufw", default="ufw.log", help="Caminho do log UFW")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Encaminhamento
    if args.command == "scan":
        handle_scan(args)
    elif args.command == "synflood" or args.command == "udpflood":
        handle_flood(args)
    elif args.command == "knock":
        handle_knock(args)
    elif args.command == "logs":
        handle_logs(args)

if __name__ == "__main__":
    # Verifica privilégios root (necessário para Scapy e Logs)
    if os.geteuid() != 0:
        print("[!] AVISO: Este script deve ser executado como ROOT (sudo).")
        sys.exit(1)
    main()