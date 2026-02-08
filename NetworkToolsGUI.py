import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import socket
import os
import re
import sqlite3

# Importa as tuas funções externas
from SynScan import syn_scan
from SynFlood import syn_flood
from UdpFlood import udp_flood
from port_knocking import execute_knocking, check_ssh_status
from log_analyzer_cli import analyze_logs_logic, get_db_stats # NOVO IMPORT

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
    # 4. LOG ANALYZER)
    # =========================================================================
    def create_log_analyzer_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Log Analyzer")
        
        config_frame = ttk.LabelFrame(frame, text="Configuração", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
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

        def run_analysis_thread():
            # Função para atualizar o texto na GUI (callback)
            def gui_callback(msg):
                self.update_log_output(msg)

            # --- AQUI ESTÁ A MAGIA ---
            # Chama a função que está no ficheiro log_analyzer_cli.py
            # Isto evita a duplicação de código!
            success = analyze_logs_logic(ssh_log, ufw_log, callback=gui_callback)
            
            if success:
                self.generate_gui_report()
            
            self.log_button.config(state=tk.NORMAL)
        
        threading.Thread(target=run_analysis_thread, daemon=True).start()

    def generate_gui_report(self):
        """Usa a função auxiliar do CLI para obter dados e mostrar na GUI"""
        try:
            stats = get_db_stats() # Função importada do log_analyzer_cli
            
            self.update_log_output("\n" + "="*40)
            self.update_log_output("   RELATÓRIO FINAL (GUI)")
            self.update_log_output("="*40)
            self.update_log_output(f"Total Eventos: {stats.get('total', 0)}")
            
            self.update_log_output("\n[TOP AMEAÇAS]")
            for ip in stats.get('top_ips', []):
                self.update_log_output(f"🔴 {ip['ip']} ({ip['pais']})")
                self.update_log_output(f"   ↳ {ip['count']} ataques | Porta: {ip['porta']}")

        except Exception as e:
            self.update_log_output(f"Erro ao ler relatório: {e}")

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
            
            c.setFont("Helvetica-Bold", 18)
            c.drawString(50, y, "Relatório de Segurança (PDF)")
            y -= 40
            
            conn = sqlite3.connect("log_analysis.db")
            cur = conn.cursor()
            
            # Resumo
            cur.execute("SELECT COUNT(*) FROM log_entries")
            total = cur.fetchone()[0]
            c.setFont("Helvetica", 12)
            c.drawString(50, y, f"Total de Eventos: {total}")
            y -= 20
            
            # Top IPs
            c.drawString(50, y, "Top 5 Atacantes:")
            y -= 20
            cur.execute("SELECT ip_origem, pais, COUNT(*) as c FROM log_entries GROUP BY ip_origem ORDER BY c DESC LIMIT 5")
            for row in cur.fetchall():
                c.drawString(60, y, f"{row[0]} ({row[1]}) - {row[2]} ataques")
                y -= 15
            
            c.save()
            conn.close()
            messagebox.showinfo("Sucesso", "PDF Gerado!")
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