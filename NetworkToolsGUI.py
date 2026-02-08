import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from SynScan import syn_scan
from SynFlood import syn_flood
from UdpFlood import udp_flood
from port_knocking import execute_knocking, check_ssh_status

class NetworkToolsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tools Suite")
        self.root.geometry("600x500")
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

    def create_syn_scan_tab(self):
        """Create SYN Scan tool tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="SYN Scan")
        
        # Input section
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # IP Input
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.syn_ip_entry = ttk.Entry(input_frame, width=30)
        self.syn_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.syn_ip_entry.insert(0, "192.168.1.1")
        
        # Ports Input
        ttk.Label(input_frame, text="Portos (ex: 80,443,8080):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.syn_ports_entry = ttk.Entry(input_frame, width=30)
        self.syn_ports_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.syn_ports_entry.insert(0, "22,80,443")
        
        input_frame.columnconfigure(1, weight=1)
        
        # Output section
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.syn_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.syn_output.pack(fill=tk.BOTH, expand=True)
        
        # Button section
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.syn_button = ttk.Button(button_frame, text="Iniciar Scan", command=self.start_syn_scan)
        self.syn_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpar", command=self.clear_syn_output).pack(side=tk.LEFT, padx=5)
        
    def create_syn_flood_tab(self):
        """Create SYN Flood tool tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="SYN Flood")
        
        # Input section
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # IP Input
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.synflood_ip_entry = ttk.Entry(input_frame, width=30)
        self.synflood_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.synflood_ip_entry.insert(0, "192.168.1.1")
        
        # Port Input
        ttk.Label(input_frame, text="Porto:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.synflood_port_entry = ttk.Entry(input_frame, width=30)
        self.synflood_port_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.synflood_port_entry.insert(0, "80")
        
        # Packets Input
        ttk.Label(input_frame, text="Número de Pacotes:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.synflood_packets_entry = ttk.Entry(input_frame, width=30)
        self.synflood_packets_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.synflood_packets_entry.insert(0, "1000")
        
        input_frame.columnconfigure(1, weight=1)
        
        # Output section
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.synflood_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.synflood_output.pack(fill=tk.BOTH, expand=True)
        
        # Button section
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.synflood_button = ttk.Button(button_frame, text="Iniciar Flood", command=self.start_syn_flood)
        self.synflood_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpar", command=self.clear_synflood_output).pack(side=tk.LEFT, padx=5)
        
    def create_udp_flood_tab(self):
        """Create UDP Flood tool tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="UDP Flood")
        
        # Input section
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # IP Input
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.udp_ip_entry = ttk.Entry(input_frame, width=30)
        self.udp_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.udp_ip_entry.insert(0, "192.168.1.1")
        
        # Port Input
        ttk.Label(input_frame, text="Porto:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.udp_port_entry = ttk.Entry(input_frame, width=30)
        self.udp_port_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.udp_port_entry.insert(0, "53")
        
        # Packets Input
        ttk.Label(input_frame, text="Número de Pacotes:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.udp_packets_entry = ttk.Entry(input_frame, width=30)
        self.udp_packets_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.udp_packets_entry.insert(0, "1000")
        
        input_frame.columnconfigure(1, weight=1)
        
        # Output section
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.udp_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.udp_output.pack(fill=tk.BOTH, expand=True)
        
        # Button section
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.udp_button = ttk.Button(button_frame, text="Iniciar Flood", command=self.start_udp_flood)
        self.udp_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpar", command=self.clear_udp_output).pack(side=tk.LEFT, padx=5)
        
    def create_log_analyzer_tab(self):
        """Create Log Analyzer tool tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Log Analyzer")
        
        # Configuration section
        config_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Log file path
        ttk.Label(config_frame, text="Caminho SSH Log:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.log_ssh_entry = ttk.Entry(config_frame, width=30)
        self.log_ssh_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.log_ssh_entry.insert(0, "/home/kali/LPD-TrabalhoIndividual/LPD-TrabalhoIndividual/auth.log")
        
        # UFW log path
        ttk.Label(config_frame, text="Caminho UFW Log:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.log_ufw_entry = ttk.Entry(config_frame, width=30)
        self.log_ufw_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.log_ufw_entry.insert(0, "/home/kali/LPD-TrabalhoIndividual/LPD-TrabalhoIndividual/ufw.log")
        
        config_frame.columnconfigure(1, weight=1)
        
        # Output section
        output_frame = ttk.LabelFrame(frame, text="Relatório", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.log_output.pack(fill=tk.BOTH, expand=True)
        
        # Button section
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.log_button = ttk.Button(button_frame, text="Analisar Logs", command=self.start_log_analysis)
        self.log_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpar", command=self.clear_log_output).pack(side=tk.LEFT, padx=5)
        
    def create_port_knocking_tab(self):
        """Create Port Knocking tool tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Port Knocking")
        
        # Input section
        input_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # IP Input
        ttk.Label(input_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pk_ip_entry = ttk.Entry(input_frame, width=30)
        self.pk_ip_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.pk_ip_entry.insert(0, "192.168.1.1")
        
        # Ports Input
        ttk.Label(input_frame, text="Sequência de Portos (ex: 1000,2000,3000):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.pk_ports_entry = ttk.Entry(input_frame, width=30)
        self.pk_ports_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.pk_ports_entry.insert(0, "1000,2000,3000")
        
        # SSH Port
        ttk.Label(input_frame, text="Porto SSH a Verificar:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pk_ssh_port_entry = ttk.Entry(input_frame, width=30)
        self.pk_ssh_port_entry.grid(row=2, column=1, sticky=tk.EW, pady=5)
        self.pk_ssh_port_entry.insert(0, "22")
        
        input_frame.columnconfigure(1, weight=1)
        
        # Output section
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.pk_output = scrolledtext.ScrolledText(output_frame, height=12, width=50, state=tk.DISABLED)
        self.pk_output.pack(fill=tk.BOTH, expand=True)
        
        # Button section
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.pk_button = ttk.Button(button_frame, text="Executar Knocking", command=self.start_port_knocking)
        self.pk_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpar", command=self.clear_pk_output).pack(side=tk.LEFT, padx=5)
        
    def update_syn_output(self, message):
        """Update SYN scan output"""
        self.syn_output.config(state=tk.NORMAL)
        self.syn_output.insert(tk.END, message + "\n")
        self.syn_output.see(tk.END)
        self.syn_output.config(state=tk.DISABLED)
        self.root.update()
        
    def update_udp_output(self, message):
        """Update UDP flood output"""
        self.udp_output.config(state=tk.NORMAL)
        self.udp_output.insert(tk.END, message + "\n")
        self.udp_output.see(tk.END)
        self.udp_output.config(state=tk.DISABLED)
        self.root.update()
        
    def update_synflood_output(self, message):
        """Update SYN flood output"""
        self.synflood_output.config(state=tk.NORMAL)
        self.synflood_output.insert(tk.END, message + "\n")
        self.synflood_output.see(tk.END)
        self.synflood_output.config(state=tk.DISABLED)
        self.root.update()
        
    def update_log_output(self, message):
        """Update Log analyzer output"""
        self.log_output.config(state=tk.NORMAL)
        self.log_output.insert(tk.END, message + "\n")
        self.log_output.see(tk.END)
        self.log_output.config(state=tk.DISABLED)
        self.root.update()
        
    def update_pk_output(self, message):
        """Update Port Knocking output"""
        self.pk_output.config(state=tk.NORMAL)
        self.pk_output.insert(tk.END, message + "\n")
        self.pk_output.see(tk.END)
        self.pk_output.config(state=tk.DISABLED)
        self.root.update()
        
    def clear_syn_output(self):
        """Clear SYN scan output"""
        self.syn_output.config(state=tk.NORMAL)
        self.syn_output.delete(1.0, tk.END)
        self.syn_output.config(state=tk.DISABLED)
        
    def clear_synflood_output(self):
        """Clear SYN flood output"""
        self.synflood_output.config(state=tk.NORMAL)
        self.synflood_output.delete(1.0, tk.END)
        self.synflood_output.config(state=tk.DISABLED)
        
    def clear_log_output(self):
        """Clear Log analyzer output"""
        self.log_output.config(state=tk.NORMAL)
        self.log_output.delete(1.0, tk.END)
        self.log_output.config(state=tk.DISABLED)
        
    def clear_udp_output(self):
        """Clear UDP flood output"""
        self.udp_output.config(state=tk.NORMAL)
        self.udp_output.delete(1.0, tk.END)
        self.udp_output.config(state=tk.DISABLED)
        
    def clear_pk_output(self):
        """Clear Port Knocking output"""
        self.pk_output.config(state=tk.NORMAL)
        self.pk_output.delete(1.0, tk.END)
        self.pk_output.config(state=tk.DISABLED)
        
    def start_syn_scan(self):
        """Start SYN scan in a separate thread"""
        target_ip = self.syn_ip_entry.get()
        ports_str = self.syn_ports_entry.get()
        
        if not target_ip or not ports_str:
            messagebox.showerror("Erro", "Por favor preencha todos os campos")
            return
        
        try:
            ports = [int(port.strip()) for port in ports_str.split(",")]
        except ValueError:
            messagebox.showerror("Erro", "Portos inválidos. Use números separados por virgula")
            return
        
        self.clear_syn_output()
        self.syn_button.config(state=tk.DISABLED)
        
        def run_scan():
            try:
                self.update_syn_output(f"--- A iniciar varrimento SYN em {target_ip} ---")
                open_ports = syn_scan(target_ip, ports, callback=self.update_syn_output)
                
                self.update_syn_output(f"\n--- Resultado Final ---")
                self.update_syn_output(f"Total de portos abertos: {len(open_ports)}")
                if open_ports:
                    self.update_syn_output(f"Portos abertos: {open_ports}")
                else:
                    self.update_syn_output("Nenhum porto aberto foi encontrado.")
            except Exception as e:
                self.update_syn_output(f"Erro: {str(e)}")
            finally:
                self.syn_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
    def start_syn_flood(self):
        """Start SYN flood in a separate thread"""
        target_ip = self.synflood_ip_entry.get()
        port_str = self.synflood_port_entry.get()
        packets_str = self.synflood_packets_entry.get()
        
        if not target_ip or not port_str or not packets_str:
            messagebox.showerror("Erro", "Por favor preencha todos os campos")
            return
        
        try:
            port = int(port_str)
            packets = int(packets_str)
        except ValueError:
            messagebox.showerror("Erro", "Porto e número de pacotes devem ser números inteiros")
            return
        
        # Confirmation dialog
        if not messagebox.askyesno("Confirmação", 
                                   f"Tem a certeza que deseja iniciar SYN Flood para {target_ip}:{port}?"):
            return
        
        self.clear_synflood_output()
        self.synflood_button.config(state=tk.DISABLED)
        
        def run_flood():
            try:
                total_sent = syn_flood(target_ip, port, packets, callback=self.update_synflood_output)
                self.update_synflood_output(f"\nFlood terminado. Total de pacotes enviados: {total_sent}")
            except Exception as e:
                self.update_synflood_output(f"Erro: {str(e)}")
            finally:
                self.synflood_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_flood, daemon=True)
        thread.start()
        
    def start_udp_flood(self):
        """Start UDP flood in a separate thread"""
        target_ip = self.udp_ip_entry.get()
        port_str = self.udp_port_entry.get()
        packets_str = self.udp_packets_entry.get()
        
        if not target_ip or not port_str or not packets_str:
            messagebox.showerror("Erro", "Por favor preencha todos os campos")
            return
        
        try:
            port = int(port_str)
            packets = int(packets_str)
        except ValueError:
            messagebox.showerror("Erro", "Porto e número de pacotes devem ser números inteiros")
            return
        
        # Confirmation dialog
        if not messagebox.askyesno("Confirmação", 
                                   f"Tem a certeza que deseja iniciar UDP Flood para {target_ip}:{port}?"):
            return
        
        self.clear_udp_output()
        self.udp_button.config(state=tk.DISABLED)
        
        def run_flood():
            try:
                total_sent = udp_flood(target_ip, port, packets, callback=self.update_udp_output)
                self.update_udp_output(f"\nFlood terminado. Total de pacotes enviados: {total_sent}")
            except Exception as e:
                self.update_udp_output(f"Erro: {str(e)}")
            finally:
                self.udp_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_flood, daemon=True)
        thread.start()
        
    def start_port_knocking(self):
        """Start port knocking in a separate thread"""
        target_ip = self.pk_ip_entry.get()
        ports_str = self.pk_ports_entry.get()
        ssh_port_str = self.pk_ssh_port_entry.get()
        
        if not target_ip or not ports_str or not ssh_port_str:
            messagebox.showerror("Erro", "Por favor preencha todos os campos")
            return
        
        try:
            ports = [int(port.strip()) for port in ports_str.split(",")]
            ssh_port = int(ssh_port_str)
        except ValueError:
            messagebox.showerror("Erro", "Portos devem ser números inteiros separados por virgula")
            return
        
        # Confirmation dialog
        if not messagebox.askyesno("Confirmação", 
                                   f"Tem a certeza que deseja executar Port Knocking em {target_ip}?"):
            return
        
        self.clear_pk_output()
        self.pk_button.config(state=tk.DISABLED)
        
        def run_knocking():
            try:
                self.update_pk_output(f"--- A executar Port Knocking em {target_ip} ---")
                self.update_pk_output(f"Sequência de portos: {ports}")
                self.update_pk_output(f"Porto SSH: {ssh_port}\n")
                
                # Check initial SSH status
                self.update_pk_output("Verificando status SSH inicial...")
                initial_status = check_ssh_status(target_ip, ssh_port)
                self.update_pk_output(f"SSH {'ABERTO' if initial_status else 'FECHADO'} antes do knocking")
                
                # Execute knocking
                success = execute_knocking(target_ip, ports, callback=self.update_pk_output)
                
                if success:
                    self.update_pk_output(f"\n✓ Knocking executado com sucesso!")
                else:
                    self.update_pk_output(f"\n⚠ Knocking concluído com avisos")
                
                # Wait a moment and check SSH status again
                self.update_pk_output("\nAguardando 2 segundos antes de verificar SSH...")
                import time
                time.sleep(2)
                
                self.update_pk_output("Verificando status SSH após knocking...")
                final_status = check_ssh_status(target_ip, ssh_port)
                self.update_pk_output(f"SSH {'ABERTO' if final_status else 'FECHADO'} após knocking")
                
                # Summary
                self.update_pk_output("\n--- RESUMO ---")
                self.update_pk_output(f"Antes: {'ABERTO' if initial_status else 'FECHADO'}")
                self.update_pk_output(f"Depois: {'ABERTO' if final_status else 'FECHADO'}")
                if final_status and not initial_status:
                    self.update_pk_output("✓ Port Knocking funcionou!")
                elif final_status:
                    self.update_pk_output("⚠ SSH já estava aberto")
                else:
                    self.update_pk_output("✗ Knocking não abriu a porta SSH")
                    
            except Exception as e:
                self.update_pk_output(f"Erro: {str(e)}")
                import traceback
                self.update_pk_output(f"Traceback: {traceback.format_exc()}")
            finally:
                self.pk_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_knocking, daemon=True)
        thread.start()
    def start_log_analysis(self):
        """Start log analysis in a separate thread"""
        ssh_log = self.log_ssh_entry.get()
        ufw_log = self.log_ufw_entry.get()
        
        if not ssh_log and not ufw_log:
            messagebox.showerror("Erro", "Por favor preencha pelo menos um caminho de log")
            return
        
        self.clear_log_output()
        self.log_button.config(state=tk.DISABLED)
        
        # Função auxiliar de GeoIP (definida aqui para correr na thread)
        def get_country(ip):
            import requests
            import time
            
            # Filtra IPs privados
            if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
                return "Rede Local (LAN)"
            
            # Cache simples para não bloquear a API
            if not hasattr(get_country, 'cache'):
                get_country.cache = {}
            
            if ip in get_country.cache:
                return get_country.cache[ip]
            
            try:
                time.sleep(0.1) # Respeitar rate-limit da API
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country = data.get('country', 'Desconhecido')
                        get_country.cache[ip] = country
                        return country
            except:
                pass
            return "Desconhecido"

        def run_analysis():
            try:
                import os
                import re
                import sqlite3
                
                self.update_log_output("--- A iniciar análise de logs ---")
                
                # Setup Base de Dados
                db_path = "log_analysis.db"
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Recriar tabela para garantir estrutura correta
                cursor.execute("DROP TABLE IF EXISTS log_entries")
                cursor.execute('''
                    CREATE TABLE log_entries (
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
                
                total_ssh = 0
                total_ufw = 0

                # --- 1. PROCESSAR SSH ---
                if os.path.exists(ssh_log):
                    self.update_log_output(f"\nA ler SSH: {ssh_log}")
                    # Regex para falhas de password e utilizadores inválidos
                    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
                    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
                    
                    with open(ssh_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_fail, line)
                            if match:
                                ts, user, ip = match.groups()
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "SSH", "Falha Password", user, ip, country))
                                total_ssh += 1
                            else:
                                match = re.search(regex_invalid, line)
                                if match:
                                    ts, user, ip = match.groups()
                                    country = get_country(ip)
                                    cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "SSH", "Utilizador Inválido", user, ip, country))
                                    total_ssh += 1
                                    
                            if total_ssh % 50 == 0 and total_ssh > 0:
                                self.update_log_output(f"SSH: processados {total_ssh}...")

                    conn.commit()
                    self.update_log_output(f"Total SSH processados: {total_ssh}")
                else:
                    self.update_log_output(f"Ficheiro SSH não encontrado: {ssh_log}")

                # --- 2. PROCESSAR UFW (CORRIGIDO) ---
                if os.path.exists(ufw_log):
                    self.update_log_output(f"\nA ler UFW: {ufw_log}")
                    
                    # Regex Corrigido: DPT agora é opcional (?:DPT=(\d+))?
                    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
                    
                    with open(ufw_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_ufw, line)
                            if match:
                                ts, ip, port, proto = match.groups()
                                if port is None: port = "N/A" # Se não tiver porta (ex: PROTO=2)
                                
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "UFW", f"Bloqueio {proto}", ip, port, country))
                                total_ufw += 1
                            
                            if total_ufw % 50 == 0 and total_ufw > 0:
                                self.update_log_output(f"UFW: processados {total_ufw}...")

                    conn.commit()
                    self.update_log_output(f"Total UFW processados: {total_ufw}")
                else:
                    self.update_log_output(f"Ficheiro UFW não encontrado: {ufw_log}")
                
                # --- 3. GERAR RELATÓRIO ---
                self.update_log_output("\n\n=== RELATÓRIO DE SEGURANÇA ===")
                
                cursor.execute("SELECT COUNT(*) FROM log_entries")
                total = cursor.fetchone()[0]
                
                if total == 0:
                    self.update_log_output("AVISO: Nenhum padrão detetado. Verifique se os logs estão vazios ou se tem permissões de leitura.")
                else:
                    self.update_log_output(f"Total de eventos detetados: {total}")
                    
                    # Top Países
                    self.update_log_output("\n--- Top 5 Países de Origem ---")
                    cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries GROUP BY pais ORDER BY c DESC LIMIT 5")
                    for row in cursor.fetchall():
                        self.update_log_output(f"  {row[0]}: {row[1]}")

                    # Top IPs
                    self.update_log_output("\n--- Top 5 IPs Atacantes ---")
                    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
                    for row in cursor.fetchall():
                        self.update_log_output(f"  {row[0]} ({row[1]}): {row[2]}")

                    # Top Serviços
                    self.update_log_output("\n--- Eventos por Serviço ---")
                    cursor.execute("SELECT servico, COUNT(*) as c FROM log_entries GROUP BY servico ORDER BY c DESC")
                    for row in cursor.fetchall():
                        self.update_log_output(f"  {row[0]}: {row[1]}")

                conn.close()
                
            except Exception as e:
                self.update_log_output(f"ERRO CRÍTICO: {str(e)}")
                import traceback
                print(traceback.format_exc()) # Imprime erro detalhado no terminal
            finally:
                self.log_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
    def start_log_analysis(self):
        """Start log analysis in a separate thread"""
        ssh_log = self.log_ssh_entry.get()
        ufw_log = self.log_ufw_entry.get()
        
        if not ssh_log and not ufw_log:
            messagebox.showerror("Erro", "Por favor preencha pelo menos um caminho de log")
            return
        
        self.clear_log_output()
        self.log_button.config(state=tk.DISABLED)
        
        # Função auxiliar de GeoIP
        def get_country(ip):
            import requests
            import time
            
            # Filtra IPs privados
            if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
                return "Rede Local (LAN)"
            
            # Cache simples
            if not hasattr(get_country, 'cache'):
                get_country.cache = {}
            
            if ip in get_country.cache:
                return get_country.cache[ip]
            
            try:
                time.sleep(0.05) # Pequeno delay para a API
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country = data.get('country', 'Desconhecido')
                        get_country.cache[ip] = country
                        return country
            except:
                pass
            return "Desconhecido"

        def run_analysis():
            try:
                import os
                import re
                import sqlite3
                
                self.update_log_output("--- A iniciar análise de logs ---")
                
                # Setup Base de Dados
                db_path = "log_analysis.db"
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Recriar tabela
                cursor.execute("DROP TABLE IF EXISTS log_entries")
                cursor.execute('''
                    CREATE TABLE log_entries (
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
                
                total_ssh = 0
                total_ufw = 0

                # --- 1. PROCESSAR SSH ---
                if os.path.exists(ssh_log):
                    self.update_log_output(f"\nA ler SSH: {ssh_log}")
                    # Regex para falhas
                    regex_fail = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
                    regex_invalid = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
                    
                    with open(ssh_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_fail, line)
                            if match:
                                ts, user, ip = match.groups()
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "SSH", "Falha Password", user, ip, country))
                                total_ssh += 1
                            else:
                                match = re.search(regex_invalid, line)
                                if match:
                                    ts, user, ip = match.groups()
                                    country = get_country(ip)
                                    cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, user, ip_origem, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "SSH", "Utilizador Inválido", user, ip, country))
                                    total_ssh += 1
                            
                            if total_ssh % 100 == 0 and total_ssh > 0:
                                self.update_log_output(f"SSH: processados {total_ssh}...")

                    conn.commit()
                else:
                    self.update_log_output(f"Ficheiro SSH não encontrado: {ssh_log}")

                # --- 2. PROCESSAR UFW ---
                if os.path.exists(ufw_log):
                    self.update_log_output(f"\nA ler UFW: {ufw_log}")
                    # Regex Flexivel (DPT opcional)
                    regex_ufw = r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*(?:DPT=(\d+))?.*PROTO=(\w+)'
                    
                    with open(ufw_log, 'r') as f:
                        for line in f:
                            match = re.search(regex_ufw, line)
                            if match:
                                ts, ip, port, proto = match.groups()
                                if port is None: port = "N/A"
                                country = get_country(ip)
                                cursor.execute("INSERT INTO log_entries (timestamp, servico, tipo_evento, ip_origem, porta_alvo, pais) VALUES (?,?,?,?,?,?)",
                                             (ts, "UFW", f"Bloqueio {proto}", ip, port, country))
                                total_ufw += 1
                            
                            if total_ufw % 100 == 0 and total_ufw > 0:
                                self.update_log_output(f"UFW: processados {total_ufw}...")

                    conn.commit()
                else:
                    self.update_log_output(f"Ficheiro UFW não encontrado: {ufw_log}")
                
                # --- 3. GERAR RELATÓRIO DETALHADO ---
                self.update_log_output("\n" + "="*40)
                self.update_log_output("   RELATÓRIO DE SEGURANÇA FINAL")
                self.update_log_output("="*40)
                
                cursor.execute("SELECT COUNT(*) FROM log_entries")
                total = cursor.fetchone()[0]
                
                if total == 0:
                    self.update_log_output("AVISO: Nenhuns dados encontrados.")
                else:
                    # 1. TIMESTAMPS (O teu pedido específico)
                    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM log_entries")
                    times = cursor.fetchone()
                    self.update_log_output(f"\n[TIMESTAMPS]")
                    self.update_log_output(f"Primeiro Evento: {times[0]}")
                    self.update_log_output(f"Último Evento:   {times[1]}")

                    # 2. ÚLTIMO ATAQUE REGISTADO (Detalhe)
                    cursor.execute("SELECT timestamp, servico, ip_origem, pais, tipo_evento FROM log_entries ORDER BY id DESC LIMIT 1")
                    last = cursor.fetchone()
                    if last:
                        self.update_log_output(f"\n[MAIS RECENTE REGISTADO]")
                        self.update_log_output(f"Hora:   {last[0]}")
                        self.update_log_output(f"Origem: {last[2]} ({last[3]})")
                        self.update_log_output(f"Tipo:   {last[1]} - {last[4]}")

                    # 3. LISTA DE PAÍSES (O teu pedido específico)
                    self.update_log_output(f"\n[DISTRIBUIÇÃO POR PAÍS]")
                    cursor.execute("SELECT pais, COUNT(*) as c FROM log_entries WHERE pais IS NOT NULL GROUP BY pais ORDER BY c DESC LIMIT 10")
                    for row in cursor.fetchall():
                        self.update_log_output(f"  {row[0]:<20} | {row[1]} tentativas")

                    # 4. TOP IPs
                    self.update_log_output(f"\n[TOP 5 IPs ATACANTES]")
                    cursor.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
                    for row in cursor.fetchall():
                        self.update_log_output(f"  {row[0]:<15} ({row[1]}) : {row[2]}")

                    self.update_log_output(f"\nTotal Processado: {total} eventos")
                    self.update_log_output(f"Base de Dados guardada em: {db_path}")

                conn.close()
                
            except Exception as e:
                self.update_log_output(f"ERRO CRÍTICO: {str(e)}")
                import traceback
                print(traceback.format_exc())
            finally:
                self.log_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()



        """Cria a aba de Port Knocking"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Port Knocking")
        
        config_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # IP
        ttk.Label(config_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W)
        self.knock_ip_entry = ttk.Entry(config_frame, width=30)
        self.knock_ip_entry.grid(row=0, column=1, pady=5)
        self.knock_ip_entry.insert(0, "127.0.0.1")
        
        # Sequência
        ttk.Label(config_frame, text="Sequência (ex: 7000,8000,9000):").grid(row=1, column=0, sticky=tk.W)
        self.knock_seq_entry = ttk.Entry(config_frame, width=30)
        self.knock_seq_entry.grid(row=1, column=1, pady=5)
        self.knock_seq_entry.insert(0, "7000,8000,9000")
        
        # Output
        self.knock_output = scrolledtext.ScrolledText(frame, height=10, state=tk.DISABLED)
        self.knock_output.pack(fill=tk.BOTH, expand=True, padx=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        self.knock_btn = ttk.Button(btn_frame, text="Executar Knock", command=self.start_knocking)
        self.knock_btn.pack(side=tk.LEFT, padx=5)
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolsGUI(root)
    root.mainloop()