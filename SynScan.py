from scapy.all import IP, TCP, sr1

def syn_scan(target_ip, ports, callback=None):
    """
    Perform a SYN scan on target IP and ports.
    
    Args:
        target_ip: Target IP address
        ports: List of ports to scan
        callback: Optional function to call for progress updates
        
    Returns:
        List of open ports
    """
    open_ports = []
    
    for i, port in enumerate(ports):
        if callback:
            callback(f"Verificando porto {port}...")
        
        # Criamos um pacote IP com destino ao alvo e um pacote TCP com a flag 'S' (SYN)
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        # Enviamos o pacote e esperamos por 1 resposta (timeout de 1s)
        response = sr1(packet, timeout=1, verbose=0)
        
        if response:
            # Se recebermos SYN-ACK (flags=0x12 ou 18), o porto está aberto
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                if callback:
                    callback(f"[+] Porto {port} está ABERTO")
                # Enviamos um RST para fechar a ligação educadamente
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
    
    return open_ports