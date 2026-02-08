import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import socket
import os
import re
import sqlite3

# Importa as tuas funções externas
# Certifica-te que os ficheiros SynScan.py, SynFlood.py, UdpFlood.py e port_knocking.py existem
from SynScan import syn_scan
from SynFlood import syn_flood
from UdpFlood import udp_flood
from port_knocking import execute_knocking, check_ssh_status

class NetworkToolsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tools Suite")
        self.root.geometry("600x650")
        self.root.resizable(True, True)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add tabs for each tool
        self.create_syn_scan_tab()
        self.create_syn_flood_tab()
        self.create_udp_flood_tab()
        self.create_log_analyzer_tab()
        self.create_port_knocking_tab()

    # =========================================================================
    # 1. SYN SCAN
    # =========================================================================
    def create_syn_scan_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="SYN Scan")
        
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.syn_ip_entry = ttk.Entry(input_frame, width=30)
        self.syn_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.syn_ip_entry.insert(0, "192.168.1.1")
        
        ttk.Label(input_frame, text="Portos (ex: 80,443):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.syn_ports_entry = ttk.Entry(input_frame, width=30)
        self.syn_ports_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.syn_ports_entry.insert(0, "22,80,443")
        
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.syn_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.syn_output.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.syn_button = ttk.Button(button_frame, text="Iniciar Scan", command=self.start_syn_scan)
        self.syn_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_syn_output).pack(side=tk.LEFT, padx=5)

    def start_syn_scan(self):
        target_ip = self.syn_ip_entry.get()
        ports_str = self.syn_ports_entry.get()
        
        if not target_ip or not ports_str:
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        
        try:
            ports = [int(p.strip()) for p in ports_str.split(",")]
        except ValueError:
            messagebox.showerror("Erro", "Portos inválidos")
            return
        
        self.clear_syn_output()
        self.syn_button.config(state=tk.DISABLED)
        
        def run_scan():
            try:
                self.update_syn_output(f"--- A iniciar varrimento SYN em {target_ip} ---")
                open_ports = syn_scan(target_ip, ports, callback=self.update_syn_output)
                self.update_syn_output(f"\nTotal abertos: {len(open_ports)}")
            except Exception as e:
                self.update_syn_output(f"Erro: {str(e)}")
            finally:
                self.syn_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_scan, daemon=True).start()

    def update_syn_output(self, message):
        self.syn_output.config(state=tk.NORMAL)
        self.syn_output.insert(tk.END, message + "\n")
        self.syn_output.see(tk.END)
        self.syn_output.config(state=tk.DISABLED)
        self.root.update()

    def clear_syn_output(self):
        self.syn_output.config(state=tk.NORMAL)
        self.syn_output.delete(1.0, tk.END)
        self.syn_output.config(state=tk.DISABLED)

    # =========================================================================
    # 2. SYN FLOOD
    # =========================================================================
    def create_syn_flood_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="SYN Flood")
        
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.synflood_ip_entry = ttk.Entry(input_frame, width=30)
        self.synflood_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.synflood_ip_entry.insert(0, "192.168.1.1")
        
        ttk.Label(input_frame, text="Porto:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.synflood_port_entry = ttk.Entry(input_frame, width=30)
        self.synflood_port_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.synflood_port_entry.insert(0, "80")
        
        ttk.Label(input_frame, text="Pacotes:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.synflood_packets_entry = ttk.Entry(input_frame, width=30)
        self.synflood_packets_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.synflood_packets_entry.insert(0, "1000")
        
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.synflood_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.synflood_output.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.synflood_button = ttk.Button(button_frame, text="Iniciar Flood", command=self.start_syn_flood)
        self.synflood_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_synflood_output).pack(side=tk.LEFT, padx=5)

    def start_syn_flood(self):
        target_ip = self.synflood_ip_entry.get()
        port_str = self.synflood_port_entry.get()
        packets_str = self.synflood_packets_entry.get()
        
        if not target_ip or not port_str or not packets_str:
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        
        if not messagebox.askyesno("Confirmação", f"Iniciar SYN Flood para {target_ip}?"):
            return
        
        self.clear_synflood_output()
        self.synflood_button.config(state=tk.DISABLED)
        
        def run_flood():
            try:
                total_sent = syn_flood(target_ip, int(port_str), int(packets_str), callback=self.update_synflood_output)
                self.update_synflood_output(f"\nFlood terminado. Total: {total_sent}")
            except Exception as e:
                self.update_synflood_output(f"Erro: {str(e)}")
            finally:
                self.synflood_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_flood, daemon=True).start()

    def update_synflood_output(self, message):
        self.synflood_output.config(state=tk.NORMAL)
        self.synflood_output.insert(tk.END, message + "\n")
        self.synflood_output.see(tk.END)
        self.synflood_output.config(state=tk.DISABLED)
        self.root.update()

    def clear_synflood_output(self):
        self.synflood_output.config(state=tk.NORMAL)
        self.synflood_output.delete(1.0, tk.END)
        self.synflood_output.config(state=tk.DISABLED)

    # =========================================================================
    # 3. UDP FLOOD
    # =========================================================================
    def create_udp_flood_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="UDP Flood")
        
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.udp_ip_entry = ttk.Entry(input_frame, width=30)
        self.udp_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.udp_ip_entry.insert(0, "192.168.1.1")
        
        ttk.Label(input_frame, text="Porto:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.udp_port_entry = ttk.Entry(input_frame, width=30)
        self.udp_port_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.udp_port_entry.insert(0, "53")
        
        ttk.Label(input_frame, text="Pacotes:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.udp_packets_entry = ttk.Entry(input_frame, width=30)
        self.udp_packets_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.udp_packets_entry.insert(0, "1000")
        
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.udp_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.udp_output.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.udp_button = ttk.Button(button_frame, text="Iniciar Flood", command=self.start_udp_flood)
        self.udp_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_udp_output).pack(side=tk.LEFT, padx=5)

    def start_udp_flood(self):
        target_ip = self.udp_ip_entry.get()
        port_str = self.udp_port_entry.get()
        packets_str = self.udp_packets_entry.get()
        
        if not target_ip or not port_str or not packets_str:
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        
        if not messagebox.askyesno("Confirmação", f"Iniciar UDP Flood para {target_ip}?"):
            return
        
        self.clear_udp_output()
        self.udp_button.config(state=tk.DISABLED)
        
        def run_flood():
            try:
                total_sent = udp_flood(target_ip, int(port_str), int(packets_str), callback=self.update_udp_output)
                self.update_udp_output(f"\nFlood terminado. Total: {total_sent}")
            except Exception as e:
                self.update_udp_output(f"Erro: {str(e)}")
            finally:
                self.udp_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_flood, daemon=True).start()

    def update_udp_output(self, message):
        self.udp_output.config(state=tk.NORMAL)
        self.udp_output.insert(tk.END, message + "\n")
        self.udp_output.see(tk.END)
        self.udp_output.config(state=tk.DISABLED)
        self.root.update()

    def clear_udp_output(self):
        self.udp_output.config(state=tk.NORMAL)
        self.udp_output.delete(1.0, tk.END)
        self.udp_output.config(state=tk.DISABLED)

    # =========================================================================
    # 4. LOG ANALYZER
    # =========================================================================
    def create_log_analyzer_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Log Analyzer")
        
        config_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Podes ajustar estes caminhos para os teus ficheiros reais
        ttk.Label(config_frame, text="Caminho SSH Log:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.log_ssh_entry = ttk.Entry(config_frame, width=30)
        self.log_ssh_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.log_ssh_entry.insert(0, "/home/kali/LPD-TrabalhoIndividual/LPD-TrabalhoIndividual/auth.log")
        
        ttk.Label(config_frame, text="Caminho UFW Log:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.log_ufw_entry = ttk.Entry(config_frame, width=30)
        self.log_ufw_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.log_ufw_entry.insert(0, "/home/kali/LPD-TrabalhoIndividual/LPD-TrabalhoIndividual/ufw.log")
        
        output_frame = ttk.LabelFrame(frame, text="Relatório", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.log_output.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.log_button = ttk.Button(button_frame, text="Analisar Logs", command=self.start_log_analysis)
        self.log_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Exportar PDF", command=self.export_pdf_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_log_output).pack(side=tk.LEFT, padx=5)

    def start_log_analysis(self):
        ssh_log = self.log_ssh_entry.get()
        ufw_log = self.log_ufw_entry.get()
        
        if not ssh_log and not ufw_log:
            messagebox.showerror("Erro", "Preencha pelo menos um caminho de log")
            return
        
        self.clear_log_output()
        self.log_button.config(state=tk.DISABLED)
        
        # GeoIP Interno
        def get_country(ip):
            import requests
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

        def run_analysis():
            conn = None
            try:
                self.update_log_output("--- A iniciar análise forense de logs ---")
                
                # Timeout aumentado para 10s para evitar "database locked"
                db_path = "log_analysis.db"
                conn = sqlite3.connect(db_path, timeout=10)
                
                # Ativar Write-Ahead Logging para evitar bloqueios de leitura/escrita
                conn.execute("PRAGMA journal_mode=WAL")
                
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS log_entries")
                cursor.execute('''CREATE TABLE log_entries (
                        id INTEGER PRIMARY KEY, timestamp TEXT, servico TEXT, 
                        tipo_evento TEXT, user TEXT, ip_origem TEXT, porta_alvo TEXT, pais TEXT)''')
                conn.commit()
                
                total_ssh = 0
                total_ufw = 0

                # --- PROCESSAMENTO SSH ---
                if os.path.exists(ssh_log):
                    self.update_log_output(f"\n[SCAN] A ler SSH: {ssh_log}")
                    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
                    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
                    
                    with open(ssh_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_fail, line)
                            if match:
                                ts, user, ip, port = match.groups()
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Falha Password", user, ip, port, country))
                                total_ssh += 1
                            else:
                                match = re.search(regex_invalid, line)
                                if match:
                                    ts, user, ip = match.groups()
                                    country = get_country(ip)
                                    cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Utilizador Inválido", user, ip, "N/A", country))
                                    total_ssh += 1
                            
                            # Commit a cada 500 linhas para libertar a DB
                            if total_ssh % 500 == 0: 
                                conn.commit()
                                self.update_log_output(f"SSH: {total_ssh} eventos processados...")
                    conn.commit() # Commit final do SSH
                
                # --- PROCESSAMENTO UFW ---
                if os.path.exists(ufw_log):
                    self.update_log_output(f"\n[SCAN] A ler UFW: {ufw_log}")
                    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
                    
                    with open(ufw_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_ufw, line)
                            if match:
                                ts, ip, port, proto = match.groups()
                                if port is None: port = "Variável"
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "UFW", f"Bloqueio {proto}", ip, port, country))
                                total_ufw += 1
                            
                            if total_ufw % 200 == 0: 
                                conn.commit()
                                self.update_log_output(f"UFW: {total_ufw} eventos processados...")
                    conn.commit() # Commit final do UFW
                
                # ==========================================
                # GERAÇÃO DO RELATÓRIO
                # ==========================================
                self.update_log_output("\n" + "="*50)
                self.update_log_output("       RELATÓRIO DE AMEAÇAS")
                self.update_log_output("="*50)
                
                cursor.execute("SELECT COUNT(*) FROM log_entries")
                total = cursor.fetchone()[0]
                
                if total == 0:
                    self.update_log_output("Nenhum dado encontrado.")
                else:
                    # 1. TIMELINE
                    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM log_entries")
                    times = cursor.fetchone()
                    self.update_log_output(f"\n[1. PERÍODO ANALISADO]")
                    self.update_log_output(f"Início: {times[0]}")
                    self.update_log_output(f"Fim:    {times[1]}")
                    self.update_log_output(f"Total Eventos: {total}")

                    # 2. SERVIÇOS
                    self.update_log_output(f"\n[2. ALVOS DOS ATAQUES]")
                    cursor.execute("SELECT servico, COUNT(*) as c FROM log_entries GROUP BY servico ORDER BY c DESC")
                    for row in cursor.fetchall():
                        self.update_log_output(f"- {row[0]}: {row[1]} tentativas")

                    # 3. TOP USERNAMES
                    self.update_log_output(f"\n[3. UTILIZADORES MAIS TENTADOS (Brute-Force)]")
                    cursor.execute("SELECT user, COUNT(*) as c FROM log_entries WHERE user IS NOT NULL GROUP BY user ORDER BY c DESC LIMIT 5")
                    rows = cursor.fetchall()
                    if rows:
                        for r in rows:
                            self.update_log_output(f"- '{r[0]}': {r[1]} vezes")
                    else:
                        self.update_log_output("(Nenhum nome de utilizador capturado)")

                    # 4. TOP IPs
                    self.update_log_output(f"\n[4. TOP 5 ATACANTES & ORIGEM]")
                    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
                    top_ips = cursor.fetchall()
                    
                    for row in top_ips:
                        ip, pais, count = row
                        # Sub-query para porta
                        cursor.execute("SELECT porta_alvo, COUNT(*) as pc FROM log_entries WHERE ip_origem=? AND porta_alvo != 'N/A' GROUP BY porta_alvo ORDER BY pc DESC LIMIT 1", (ip,))
                        port_data = cursor.fetchone()
                        
                        if port_data:
                            porta_info = f"Porta principal: {port_data[0]}"
                        else:
                            porta_info = "Porta: Várias/Desconhecida"
                            
                        self.update_log_output(f"🔴 {ip: <15} ({pais})")
                        self.update_log_output(f"   ↳ {count} ataques | {porta_info}")

                    # 5. TOP PAÍSES
                    self.update_log_output(f"\n[5. MAPA DE ORIGEM]")
                    cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries WHERE pais IS NOT NULL GROUP BY pais ORDER BY c DESC LIMIT 5")
                    for r in cursor.fetchall():
                        self.update_log_output(f"- {r[0]}: {r[1]}")
                
                self.update_log_output("\nAnálise concluída.")
                
            except Exception as e:
                self.update_log_output(f"ERRO CRÍTICO: {str(e)}")
                import traceback
                print(traceback.format_exc())
            finally:
                if conn:
                    conn.close()
                self.log_button.config(state=tk.NORMAL)
            try:
                self.update_log_output("--- A iniciar análise forense de logs ---")
                
                conn = sqlite3.connect("log_analysis.db")
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS log_entries")
                cursor.execute('''CREATE TABLE log_entries (
                        id INTEGER PRIMARY KEY, timestamp TEXT, servico TEXT, 
                        tipo_evento TEXT, user TEXT, ip_origem TEXT, porta_alvo TEXT, pais TEXT)''')
                conn.commit()
                
                total_ssh = 0
                total_ufw = 0

                # --- PROCESSAMENTO SSH ---
                if os.path.exists(ssh_log):
                    self.update_log_output(f"\n[SCAN] A ler SSH: {ssh_log}")
                    # Regex 1: Failed password (com porta)
                    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
                    # Regex 2: Invalid user (sem porta)
                    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
                    
                    with open(ssh_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_fail, line)
                            if match:
                                ts, user, ip, port = match.groups()
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Falha Password", user, ip, port, country))
                                total_ssh += 1
                            else:
                                match = re.search(regex_invalid, line)
                                if match:
                                    ts, user, ip = match.groups()
                                    country = get_country(ip)
                                    # Marcamos porta como N/A mas o IP conta na mesma
                                    cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Utilizador Inválido", user, ip, "N/A", country))
                                    total_ssh += 1
                            
                            if total_ssh % 500 == 0: self.update_log_output(f"SSH: {total_ssh} eventos processados...")
                    conn.commit()
                
                # --- PROCESSAMENTO UFW ---
                if os.path.exists(ufw_log):
                    self.update_log_output(f"\n[SCAN] A ler UFW: {ufw_log}")
                    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
                    
                    with open(ufw_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_ufw, line)
                            if match:
                                ts, ip, port, proto = match.groups()
                                if port is None: port = "Variável"
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "UFW", f"Bloqueio {proto}", ip, port, country))
                                total_ufw += 1
                            if total_ufw % 100 == 0: self.update_log_output(f"UFW: {total_ufw} eventos processados...")
                    conn.commit()
                
                # ==========================================
                # GERAÇÃO DO RELATÓRIO MELHORADO
                # ==========================================
                self.update_log_output("\n" + "="*50)
                self.update_log_output("       RELATÓRIO DE AMEAÇAS")
                self.update_log_output("="*50)
                
                cursor.execute("SELECT COUNT(*) FROM log_entries")
                total = cursor.fetchone()[0]
                
                if total == 0:
                    self.update_log_output("Nenhum dado encontrado.")
                else:
                    # 1. TIMELINE
                    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM log_entries")
                    times = cursor.fetchone()
                    self.update_log_output(f"\n[1. PERÍODO ANALISADO]")
                    self.update_log_output(f"Início: {times[0]}")
                    self.update_log_output(f"Fim:    {times[1]}")
                    self.update_log_output(f"Total Eventos: {total}")

                    # 2. SERVIÇOS
                    self.update_log_output(f"\n[2. ALVOS DOS ATAQUES]")
                    cursor.execute("SELECT servico, COUNT(*) as c FROM log_entries GROUP BY servico ORDER BY c DESC")
                    for row in cursor.fetchall():
                        self.update_log_output(f"- {row[0]}: {row[1]} tentativas")

                    # 3. TOP USERNAMES (NOVIDADE IMPORTANTE)
                    self.update_log_output(f"\n[3. UTILIZADORES MAIS TENTADOS (Brute-Force)]")
                    cursor.execute("SELECT user, COUNT(*) as c FROM log_entries WHERE user IS NOT NULL GROUP BY user ORDER BY c DESC LIMIT 5")
                    rows = cursor.fetchall()
                    if rows:
                        for r in rows:
                            self.update_log_output(f"- '{r[0]}': {r[1]} vezes")
                    else:
                        self.update_log_output("(Nenhum nome de utilizador capturado)")

                    # 4. TOP IPs (COM LÓGICA DE PORTA MELHORADA)
                    self.update_log_output(f"\n[4. TOP 5 ATACANTES & ORIGEM]")
                    # Agrupa apenas por IP para ter o total real
                    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
                    top_ips = cursor.fetchall()
                    
                    for row in top_ips:
                        ip, pais, count = row
                        
                        # Sub-query para descobrir a porta mais frequente usada por este IP
                        cursor.execute("SELECT porta_alvo, COUNT(*) as pc FROM log_entries WHERE ip_origem=? AND porta_alvo != 'N/A' GROUP BY porta_alvo ORDER BY pc DESC LIMIT 1", (ip,))
                        port_data = cursor.fetchone()
                        
                        if port_data:
                            porta_info = f"Porta principal: {port_data[0]}"
                        else:
                            porta_info = "Porta: Várias/Desconhecida"
                            
                        self.update_log_output(f"🔴 {ip: <15} ({pais})")
                        self.update_log_output(f"   ↳ {count} ataques | {porta_info}")

                    # 5. TOP PAÍSES
                    self.update_log_output(f"\n[5. MAPA DE ORIGEM]")
                    cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries WHERE pais IS NOT NULL GROUP BY pais ORDER BY c DESC LIMIT 5")
                    for r in cursor.fetchall():
                        self.update_log_output(f"- {r[0]}: {r[1]}")
                
                conn.close()
                self.update_log_output("\nAnálise concluída. Podes exportar o PDF.")
                
            except Exception as e:
                self.update_log_output(f"Erro: {e}")
                import traceback
                print(traceback.format_exc())
            finally:
                self.log_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_analysis, daemon=True).start()
        ssh_log = self.log_ssh_entry.get()
        ufw_log = self.log_ufw_entry.get()
        
        if not ssh_log and not ufw_log:
            messagebox.showerror("Erro", "Preencha pelo menos um caminho de log")
            return
        
        self.clear_log_output()
        self.log_button.config(state=tk.DISABLED)
        
        # Helper GeoIP
        def get_country(ip):
            import requests
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

        def run_analysis():
            try:
                self.update_log_output("--- A iniciar análise ---")
                
                conn = sqlite3.connect("log_analysis.db")
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS log_entries")
                # Inclui a coluna 'porta_alvo'
                cursor.execute('''CREATE TABLE log_entries (
                        id INTEGER PRIMARY KEY, timestamp TEXT, servico TEXT, 
                        tipo_evento TEXT, user TEXT, ip_origem TEXT, porta_alvo TEXT, pais TEXT)''')
                conn.commit()
                
                total_ssh = 0
                total_ufw = 0

                # SSH Parsing (COM Regex corrigido para a porta)
                if os.path.exists(ssh_log):
                    self.update_log_output(f"\nA ler SSH: {ssh_log}")
                    # Regex 1: Failed password (com porta)
                    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
                    # Regex 2: Invalid user (sem porta, assume-se N/A)
                    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
                    
                    with open(ssh_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_fail, line)
                            if match:
                                ts, user, ip, port = match.groups()
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Falha Password", user, ip, port, country))
                                total_ssh += 1
                            else:
                                match = re.search(regex_invalid, line)
                                if match:
                                    ts, user, ip = match.groups()
                                    country = get_country(ip)
                                    cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?,?)",
                                             (ts, "SSH", "Utilizador Inválido", user, ip, "N/A", country))
                                    total_ssh += 1
                            
                            if total_ssh % 200 == 0: self.update_log_output(f"SSH: {total_ssh}...")
                    conn.commit()
                
                # UFW Parsing (CORRIGIDO: Removido o '?' extra)
                if os.path.exists(ufw_log):
                    self.update_log_output(f"\nA ler UFW: {ufw_log}")
                    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
                    
                    with open(ufw_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_ufw, line)
                            if match:
                                ts, ip, port, proto = match.groups()
                                if port is None: port = "N/A"
                                country = get_country(ip)
                                # CORREÇÃO AQUI: Eram 7 '?', agora são 6 para bater certo com as 6 colunas
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "UFW", f"Bloqueio {proto}", ip, port, country))
                                total_ufw += 1
                            if total_ufw % 200 == 0: self.update_log_output(f"UFW: {total_ufw}...")
                    conn.commit()
                
                # Relatório
                self.update_log_output("\n=== RELATÓRIO ===")
                cursor.execute("SELECT COUNT(*) FROM log_entries")
                total = cursor.fetchone()[0]
                self.update_log_output(f"Total Eventos: {total}")
                
                # Top IPs com Porta
                self.update_log_output("\n[TOP 5 IPs & PORTAS ALVO]")
                cursor.execute("SELECT ip_origem, porta_alvo, COUNT(*) as c FROM log_entries GROUP BY ip_origem, porta_alvo ORDER BY c DESC LIMIT 5")
                for r in cursor.fetchall():
                    self.update_log_output(f"{r[0]} (Porta {r[1]}): {r[2]} ataques")

                # Top Países
                self.update_log_output("\n[TOP 5 PAÍSES]")
                cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries GROUP BY pais ORDER BY c DESC LIMIT 5")
                for r in cursor.fetchall():
                    self.update_log_output(f"{r[0]}: {r[1]}")
                
                conn.close()
                
            except Exception as e:
                self.update_log_output(f"Erro: {e}")
                import traceback
                print(traceback.format_exc())
            finally:
                self.log_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_analysis, daemon=True).start()
    def update_log_output(self, message):
        self.log_output.config(state=tk.NORMAL)
        self.log_output.insert(tk.END, message + "\n")
        self.log_output.see(tk.END)
        self.log_output.config(state=tk.DISABLED)
        self.root.update()

    def clear_log_output(self):
        self.log_output.config(state=tk.NORMAL)
        self.log_output.delete(1.0, tk.END)
        self.log_output.config(state=tk.DISABLED)

    def export_pdf_report(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib import colors
            import sqlite3
            import datetime
            
            filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
            if not filename: return
            
            c = canvas.Canvas(filename, pagesize=letter)
            width, height = letter
            y = height - 50
            
            # Cabeçalho
            c.setFont("Helvetica-Bold", 18)
            c.drawString(50, y, "Relatório de Análise Forense")
            y -= 25
            c.setFont("Helvetica", 10)
            c.drawString(50, y, f"Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.line(50, y-10, width-50, y-10)
            y -= 40
            
            conn = sqlite3.connect("log_analysis.db")
            cur = conn.cursor()
            
            # Resumo
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "1. Resumo Executivo")
            y -= 20
            c.setFont("Helvetica", 10)
            
            cur.execute("SELECT COUNT(*) FROM log_entries")
            total = cur.fetchone()[0]
            cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM log_entries")
            times = cur.fetchone()
            
            c.drawString(60, y, f"Total Eventos: {total}")
            y -= 15
            c.drawString(60, y, f"Período: {times[0]} até {times[1]}")
            y -= 30

            # Utilizadores
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "2. Top Utilizadores Alvo (Brute-Force)")
            y -= 20
            c.setFont("Helvetica", 10)
            cur.execute("SELECT user, COUNT(*) as c FROM log_entries WHERE user IS NOT NULL GROUP BY user ORDER BY c DESC LIMIT 5")
            for row in cur.fetchall():
                c.drawString(60, y, f"User '{row[0]}': {row[1]} tentativas")
                y -= 15
            y -= 25

            # IPs Atacantes
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "3. Top 10 IPs Atacantes")
            y -= 20
            c.setFont("Helvetica", 10)
            
            cur.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 10")
            for row in cur.fetchall():
                c.drawString(60, y, f"IP: {row[0]:<15} | País: {row[1]:<15} | Ataques: {row[2]}")
                y -= 15
                if y < 50: # Nova página se necessário
                    c.showPage()
                    y = height - 50
            
            c.save()
            conn.close()
            messagebox.showinfo("Sucesso", "Relatório PDF detalhado gerado com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro PDF", str(e))
    # =========================================================================
    # 5. PORT KNOCKING
    # =========================================================================
    def create_port_knocking_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Port Knocking")
        
        config_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(config_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W)
        self.pk_ip_entry = ttk.Entry(config_frame, width=30)
        self.pk_ip_entry.grid(row=0, column=1, pady=5)
        self.pk_ip_entry.insert(0, "127.0.0.1")
        
        ttk.Label(config_frame, text="Sequência (ex: 7000,8000,9000):").grid(row=1, column=0, sticky=tk.W)
        self.pk_ports_entry = ttk.Entry(config_frame, width=30)
        self.pk_ports_entry.grid(row=1, column=1, pady=5)
        self.pk_ports_entry.insert(0, "7000,8000,9000")
        
        ttk.Label(config_frame, text="Porto SSH (ex: 22):").grid(row=2, column=0, sticky=tk.W)
        self.pk_ssh_port_entry = ttk.Entry(config_frame, width=30)
        self.pk_ssh_port_entry.grid(row=2, column=1, pady=5)
        self.pk_ssh_port_entry.insert(0, "22")
        
        self.pk_output = scrolledtext.ScrolledText(frame, height=10, state=tk.DISABLED)
        self.pk_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        self.pk_button = ttk.Button(btn_frame, text="Executar Knock", command=self.start_knocking)
        self.pk_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Limpar", command=self.clear_pk_output).pack(side=tk.LEFT, padx=5)

    def start_knocking(self):
        target = self.pk_ip_entry.get()
        seq_str = self.pk_ports_entry.get()
        try:
            ssh_port = int(self.pk_ssh_port_entry.get())
        except:
            ssh_port = 22
            
        try:
            ports = [int(p.strip()) for p in seq_str.split(",")]
        except:
            messagebox.showerror("Erro", "Sequência inválida")
            return

        self.pk_button.config(state=tk.DISABLED)
        self.update_pk_output(f"--- A iniciar Knocking para {target} ---")

        def run_knock():
            try:
                # 1. Teste Pré-Knock
                self.update_pk_output(f"[*] Teste SSH (Porta {ssh_port}) Pré-Knock...")
                if check_ssh_status(target, ssh_port):
                    self.update_pk_output("[AVISO] Porta SSH JÁ está aberta!")
                else:
                    self.update_pk_output("[OK] Porta SSH está fechada.")
                
                # 2. Executar Knock
                self.update_pk_output(f"[*] Enviando sequência: {ports}")
                execute_knocking(target, ports, callback=self.update_pk_output)
                
                # 3. Teste Pós-Knock
                time.sleep(2)
                self.update_pk_output("[*] Teste SSH Pós-Knock...")
                if check_ssh_status(target, ssh_port):
                    self.update_pk_output("[SUCESSO] Porta SSH ABERTA! Knock funcionou.")
                else:
                    self.update_pk_output("[FALHA] Porta SSH continua fechada.")
                    
            except Exception as e:
                self.update_pk_output(f"Erro: {e}")
            finally:
                self.pk_button.config(state=tk.NORMAL)

        threading.Thread(target=run_knock, daemon=True).start()

    def update_pk_output(self, msg):
        self.pk_output.config(state=tk.NORMAL)
        self.pk_output.insert(tk.END, msg + "\n")
        self.pk_output.see(tk.END)
        self.pk_output.config(state=tk.DISABLED)
        self.root.update()

    def clear_pk_output(self):
        self.pk_output.config(state=tk.NORMAL)
        self.pk_output.delete(1.0, tk.END)
        self.pk_output.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolsGUI(root)
    root.mainloop()