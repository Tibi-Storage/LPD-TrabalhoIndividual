import re
import requests
import sqlite3
import time
import os

# --- CONFIGURAÇÃO ---
LOG_FILES = {
    'ssh': 'auth.log',
    'ufw': 'ufw.log'
}
DB_NAME = 'security_logs.db'

# --- 1. FUNÇÃO DE GEOLOCALIZAÇÃO ---
geo_cache = {}

def get_country(ip):
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return "Rede Local (LAN)"
    
    if ip in geo_cache:
        return geo_cache[ip]
    
    try:
        time.sleep(0.1) 
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data['status'] == 'success':
            country = data['country']
            geo_cache[ip] = country
            return country
    except:
        return "Erro API"
    
    return "Desconhecido"

# --- 2. CONFIGURAÇÃO DA BASE DE DADOS ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ataques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            servico TEXT,
            tipo_evento TEXT,
            user TEXT,
            ip_origem TEXT,
            porta_alvo TEXT,
            pais TEXT
        )
    ''')
    conn.commit()
    return conn

# --- 3. PARSER PARA SSH (auth.log) ---
def parse_ssh(filepath, conn):
    print(f"--- A processar {filepath} (SSH) ---")
    if not os.path.exists(filepath):
        print(f"Ficheiro {filepath} não encontrado.")
        return

    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
    
    count = 0
    cursor = conn.cursor()
    
    with open(filepath, 'r') as f:
        for line in f:
            user, ip, ts, event = None, None, None, None
            
            match = re.search(regex_fail, line)
            if match:
                ts, user, ip = match.groups()
                event = "Falha Password"
            else:
                match = re.search(regex_invalid, line)
                if match:
                    ts, user, ip = match.groups()
                    event = "Utilizador Inválido"

            if ip:
                country = get_country(ip)
                cursor.execute("INSERT INTO ataques (timestamp, servico, tipo_evento, user, ip_origem, pais) VALUES (?, ?, ?, ?, ?, ?)",
                               (ts, "SSH", event, user, ip, country))
                count += 1
                
                # CORREÇÃO AQUI: Usar 'print' e a variável 'count' correta
                if count % 10 == 0: 
                    print(f"SSH processados: {count}...", end='\r')

    conn.commit()
    print(f"\nTotal SSH processado: {count}")

# --- 4. PARSER PARA FIREWALL (ufw.log) ---
# --- 4. PARSER PARA FIREWALL (ufw.log) CORRIGIDO ---
def parse_ufw(filepath, conn):
    print(f"--- A processar {filepath} (UFW) ---")
    if not os.path.exists(filepath):
        print(f"Ficheiro {filepath} não encontrado.")
        return

    # CORREÇÃO: DPT agora é opcional -> (?:DPT=(\d+))?
    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
    
    count = 0
    cursor = conn.cursor()
    
    with open(filepath, 'r') as f:
        for line in f:
            match = re.search(regex_ufw, line)
            if match:
                ts, ip, port, proto = match.groups()
                
                # Se não houver porta (ex: PROTO=2), define como N/A ou 0
                if port is None:
                    port = "N/A"
                
                country = get_country(ip)
                
                cursor.execute("INSERT INTO ataques (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?, ?, ?, ?, ?, ?)",
                               (ts, "UFW/Firewall", f"Bloqueio {proto}", ip, port, country))
                count += 1
                if count % 10 == 0: 
                    print(f"Processados {count} eventos UFW...", end='\r')

    conn.commit()
    print(f"\nTotal UFW processado: {count}")
    print(f"--- A processar {filepath} (UFW) ---")
    if not os.path.exists(filepath):
        print(f"Ficheiro {filepath} não encontrado.")
        return

    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*PROTO=(\w+)'
    
    count = 0
    cursor = conn.cursor()
    
    with open(filepath, 'r') as f:
        for line in f:
            match = re.search(regex_ufw, line)
            if match:
                ts, ip, port, proto = match.groups()
                country = get_country(ip)
                
                cursor.execute("INSERT INTO ataques (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?, ?, ?, ?, ?, ?)",
                               (ts, "UFW/Firewall", f"Bloqueio {proto}", ip, port, country))
                count += 1
                if count % 10 == 0: 
                    print(f"Processados {count} eventos UFW...", end='\r')

    conn.commit()
    print(f"\nTotal UFW processado: {count}")

# --- 5. RELATÓRIO FINAL ---
def gerar_relatorio(conn):
    cursor = conn.cursor()
    print("\n\n=== RELATÓRIO DE SEGURANÇA ===")
    
    # Top 5 Países de Origem
    print("\nTOP 5 PAÍSES ATACANTES:")
    cursor.execute("SELECT pais, COUNT(*) as c FROM ataques GROUP BY pais ORDER BY c DESC LIMIT 5")
    for row in cursor.fetchall():
        print(f"{row[0]}: {row[1]} tentativas")

    # Top 5 IPs
    print("\nTOP 5 IPs ATACANTES:")
    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM ataques GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
    for row in cursor.fetchall():
        print(f"{row[0]} ({row[1]}): {row[2]} tentativas")

def main():
    conn = init_db()
    parse_ssh(LOG_FILES['ssh'], conn)
    parse_ufw(LOG_FILES['ufw'], conn)
    gerar_relatorio(conn)
    conn.close()

if __name__ == "__main__":
    main()