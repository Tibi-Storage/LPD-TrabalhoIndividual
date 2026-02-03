"""
Log Parser Module - Extrai informações de logs SSH e HTTP
"""

import re
from datetime import datetime
from typing import List, Dict, Tuple


class SSHLogParser:
    """Parser para logs SSH"""
    
    LOG_PATHS = [
        "/var/log/auth.log",
        "/var/log/secure",
    ]
    
    def __init__(self, log_path: str = None):
        self.log_path = log_path or self.LOG_PATHS[0]
    
    def parse(self) -> List[Dict]:
        """Parse SSH logs and extract relevant information"""
        entries = []
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"Ficheiro de log não encontrado: {self.log_path}")
        
        return entries
    
    def _parse_line(self, line: str) -> Dict:
        """Parse a single SSH log line"""
        
        # Padrão para SSH authentication failed
        auth_failed = re.search(
            r'(\w+\s+\d+\s+[\d:]+).*Failed password for (\S+) from ([\d.]+) port (\d+)',
            line
        )
        if auth_failed:
            return {
                'timestamp': auth_failed.group(1),
                'user': auth_failed.group(2),
                'ip': auth_failed.group(3),
                'port': auth_failed.group(4),
                'event_type': 'Failed Password',
                'service': 'SSH'
            }
        
        # Padrão para invalid user
        invalid_user = re.search(
            r'(\w+\s+\d+\s+[\d:]+).*Invalid user (\S+) from ([\d.]+) port (\d+)',
            line
        )
        if invalid_user:
            return {
                'timestamp': invalid_user.group(1),
                'user': invalid_user.group(2),
                'ip': invalid_user.group(3),
                'port': invalid_user.group(4),
                'event_type': 'Invalid User',
                'service': 'SSH'
            }
        
        # Padrão para accepted password
        accepted = re.search(
            r'(\w+\s+\d+\s+[\d:]+).*Accepted password for (\S+) from ([\d.]+) port (\d+)',
            line
        )
        if accepted:
            return {
                'timestamp': accepted.group(1),
                'user': accepted.group(2),
                'ip': accepted.group(3),
                'port': accepted.group(4),
                'event_type': 'Accepted Password',
                'service': 'SSH'
            }
        
        return None


class HTTPLogParser:
    """Parser para logs HTTP (Apache/Nginx)"""
    
    LOG_PATHS = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]
    
    def __init__(self, log_path: str = None):
        self.log_path = log_path
        if not log_path:
            # Tenta encontrar automaticamente
            import os
            for path in self.LOG_PATHS:
                if os.path.exists(path):
                    self.log_path = path
                    break
    
    def parse(self) -> List[Dict]:
        """Parse HTTP logs and extract relevant information"""
        entries = []
        
        if not self.log_path:
            print("Nenhum ficheiro de log HTTP encontrado")
            return entries
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"Ficheiro de log não encontrado: {self.log_path}")
        
        return entries
    
    def _parse_line(self, line: str) -> Dict:
        """Parse a single HTTP log line (Apache Combined Format)"""
        
        # Padrão Apache Combined Log Format
        pattern = r'([\d.]+) - (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if match:
            ip = match.group(1)
            user = match.group(2)
            timestamp = match.group(3)
            method = match.group(4)
            path = match.group(5)
            protocol = match.group(6)
            status_code = match.group(7)
            bytes_sent = match.group(8)
            
            # Detectar tentativas inválidas (4xx, 5xx)
            event_type = "Success" if status_code.startswith('2') else "Failed Request"
            if status_code.startswith('4'):
                event_type = "Client Error"
            elif status_code.startswith('5'):
                event_type = "Server Error"
            
            return {
                'timestamp': timestamp,
                'ip': ip,
                'user': user,
                'method': method,
                'path': path,
                'status_code': int(status_code),
                'bytes_sent': bytes_sent,
                'event_type': event_type,
                'service': 'HTTP'
            }
        
        return None


class LogAnalyzer:
    """Analisador agregado de logs"""
    
    def __init__(self):
        self.ssh_parser = SSHLogParser()
        self.http_parser = HTTPLogParser()
    
    def analyze_all(self) -> Tuple[List[Dict], List[Dict]]:
        """Analisa SSH e HTTP logs"""
        ssh_entries = self.ssh_parser.parse()
        http_entries = self.http_parser.parse()
        
        return ssh_entries, http_entries
    
    def get_combined_entries(self) -> List[Dict]:
        """Retorna todos os logs combinados"""
        ssh_entries, http_entries = self.analyze_all()
        return ssh_entries + http_entries
