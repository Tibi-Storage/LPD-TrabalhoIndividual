from scapy.all import IP, TCP, sr1

def syn_scan(target_ip, ports, callback=None):
    """
    Executa um varrimento SYN (Stealth Scan).
    Retorna uma lista de portas abertas.
    """
    open_ports = []
    
    # Loop para percorrer cada porta
    for i, port in enumerate(ports):
        # Atualiza a GUI a dizer o que está a fazer
        if callback:
            callback(f"Verificando porto {port}...")
        
        # Cria pacote IP+TCP com a flag SYN (S)
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # Envia e espera 1 resposta (timeout de 1s para não encravar muito tempo)
        response = sr1(packet, timeout=1, verbose=0)
        
        if response:
            # Se recebermos SYN-ACK (flags 0x12 ou 18), o porto está ABERTO
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                
                # Avisa a GUI que encontrou uma porta
                if callback:
                    callback(f"[+] Porto {port} está ABERTO")
                
                # Envia um RST (Reset) para fechar a conexão imediatamente (Stealth)
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    
    return open_ports