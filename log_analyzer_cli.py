import sqlite3
import re
import os
import time
import requests
import argparse

# Configuração da Base de Dados
DB_NAME = 'log_analysis.db'

def get_country(ip):
    """Função auxiliar para obter GeoIP com cache simples"""
    if ip.startswith(("127.", "10.", "192.168.")): return "Rede Local"
    if not hasattr(get_country, 'cache'): get_country.cache = {}
    if ip in get_country.cache: return get_country.cache[ip]
    try:
        time.sleep(0.05)
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if r.status_code == 200 and r.json().get('status') == 'success':
            c = r.json().get('country', 'Desc.')
            get_country.cache[ip] = c
            return c
    except: pass
    return "Desconhecido"

def analyze_logs_logic(ssh_log, ufw_log, callback):
    """
    Lógica pura de análise de logs.
    Recebe caminhos dos logs e uma função de callback para reportar progresso.
    """
    try:
        callback(f"--- A iniciar análise (DB: {DB_NAME}) ---")
        
        # Timeout e WAL mode para evitar 'database locked'
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        cursor.execute("DROP TABLE IF EXISTS log_entries")
        cursor.execute('''CREATE TABLE log_entries (
                id INTEGER PRIMARY KEY, timestamp TEXT, servico TEXT, 
                tipo_evento TEXT, user TEXT, ip_origem TEXT, porta_alvo TEXT, pais TEXT)''')
        conn.commit()

        # --- PROCESSAMENTO SSH ---
        if os.path.exists(ssh_log):
            callback(f"\n[SCAN] A ler SSH: {ssh_log}")
            regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
            regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
            
            count = 0
            with open(ssh_log, 'r') as f:
                for line in f:
                    match = re.search(regex_fail, line)
                    if match:
                        ts, user, ip, port = match.groups()
                        cursor.execute("INSERT INTO log_entries VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)",
                                     (ts, "SSH", "Falha Password", user, ip, port, get_country(ip)))
                        count += 1
                    elif re.search(regex_invalid, line):
                        match = re.search(regex_invalid, line)
                        ts, user, ip = match.groups()
                        cursor.execute("INSERT INTO log_entries VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)",
                                     (ts, "SSH", "Utilizador Inválido", user, ip, "N/A", get_country(ip)))
                        count += 1
                    
                    if count % 500 == 0: conn.commit()
            conn.commit()
            callback(f"SSH Processado: {count} eventos.")

        # --- PROCESSAMENTO UFW ---
        if os.path.exists(ufw_log):
            callback(f"\n[SCAN] A ler UFW: {ufw_log}")
            regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
            
            count = 0
            with open(ufw_log, 'r') as f:
                for line in f:
                    match = re.search(regex_ufw, line)
                    if match:
                        ts, ip, port, proto = match.groups()
                        if port is None: port = "Variável"
                        cursor.execute("INSERT INTO log_entries VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)",
                                     (ts, "UFW", f"Bloqueio {proto}", None, ip, port, get_country(ip)))
                        count += 1
                        if count % 200 == 0: conn.commit()
            conn.commit()
            callback(f"UFW Processado: {count} eventos.")
        
        conn.close()
        callback("\n[SUCESSO] Base de dados atualizada.")
        return True

    except Exception as e:
        callback(f"ERRO CRÍTICO NO MOTOR: {e}")
        return False

def get_db_stats():
    """Função auxiliar para a GUI obter estatísticas"""
    stats = {}
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM log_entries")
        stats['total'] = cursor.fetchone()[0]
        
        stats['top_ips'] = []
        cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
        for row in cursor.fetchall():
            ip, pais, count = row
            cursor.execute("SELECT porta_alvo FROM log_entries WHERE ip_origem=? AND porta_alvo != 'N/A' GROUP BY porta_alvo ORDER BY COUNT(*) DESC LIMIT 1", (ip,))
            p_data = cursor.fetchone()
            porta = p_data[0] if p_data else "Várias"
            stats['top_ips'].append({'ip': ip, 'pais': pais, 'count': count, 'porta': porta})

        conn.close()
    except:
        pass
    return stats

def gerar_relatorio_texto():
    """Gera relatório de texto formatado para o Terminal (CLI)"""
    if not os.path.exists(DB_NAME):
        print("Erro: Base de dados não encontrada.")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    print("\n" + "="*60)
    print("             RELATÓRIO DE SEGURANÇA (CLI)")
    print("="*60)

    # 1. Resumo
    cursor.execute("SELECT COUNT(*) FROM log_entries")
    print(f"Total de Eventos Analisados: {cursor.fetchone()[0]}")

    # 2. Top Países
    print("\n[TOP PAÍSES DE ORIGEM]")
    cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries WHERE pais IS NOT NULL GROUP BY pais ORDER BY c DESC LIMIT 5")
    for row in cursor.fetchall():
        print(f" - {row[0]:<20}: {row[1]} ataques")

    # 3. Top IPs
    print("\n[TOP 5 IPs ATACANTES & PORTA ALVO]")
    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
    for row in cursor.fetchall():
        ip, pais, count = row
        cursor.execute("SELECT porta_alvo FROM log_entries WHERE ip_origem=? AND porta_alvo != 'N/A' GROUP BY porta_alvo ORDER BY COUNT(*) DESC LIMIT 1", (ip,))
        p_data = cursor.fetchone()
        port_info = f"(Porta: {p_data[0]})" if p_data else "(Porta: Várias)"
        print(f" 🔴 {ip:<15} ({pais}) -> {count} ataques {port_info}")

    conn.close()
    print("\n" + "="*60 + "\n")

# --- CLI EXECUTION ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", default="auth.log")
    parser.add_argument("--ufw", default="ufw.log")
    args = parser.parse_args()
    
    analyze_logs_logic(args.ssh, args.ufw, callback=print)
    gerar_relatorio_texto()