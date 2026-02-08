import socket
import time


def execute_knocking(target_ip, ports, callback=None):
    """
    Executa a sequência de knocks SYN para o IP alvo.
    """
    success_count = 0
    for port in ports:
        try:
            if callback:
                callback(f"-> Batendo na porta {port}...")
            
            # Criamos um socket TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)  # Timeout curto pois não esperamos resposta (o iptables dá DROP)
            
            # connect_ex tenta o handshake. O iptables vai registar o SYN.
            s.connect_ex((target_ip, port))
            s.close()
            
            success_count += 1
            time.sleep(0.3)  # Pausa crucial para o iptables processar a ordem
        except Exception as e:
            if callback:
                callback(f"Erro no porto {port}: {e}")
            
    return success_count == len(ports)


def check_ssh_status(target_ip, port=22):
    """
    Verifica se a porta SSH está aberta.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0  # Retorna True se estiver aberta
    except:
        return False