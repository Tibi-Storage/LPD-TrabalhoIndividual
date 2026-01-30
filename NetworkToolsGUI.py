import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from SynScan import syn_scan
from UdpFlood import udp_flood


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
        self.create_udp_flood_tab()
        
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
        
    def clear_syn_output(self):
        """Clear SYN scan output"""
        self.syn_output.config(state=tk.NORMAL)
        self.syn_output.delete(1.0, tk.END)
        self.syn_output.config(state=tk.DISABLED)
        
    def clear_udp_output(self):
        """Clear UDP flood output"""
        self.udp_output.config(state=tk.NORMAL)
        self.udp_output.delete(1.0, tk.END)
        self.udp_output.config(state=tk.DISABLED)
        
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


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolsGUI(root)
    root.mainloop()
