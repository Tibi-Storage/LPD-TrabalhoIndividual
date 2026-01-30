"""
Database Module - Gerencia dados em SQLite
"""

import sqlite3
from datetime import datetime
from typing import List, Dict
from pathlib import Path


class LogDatabase:
    """Gerencia base de dados SQLite para logs de segurança"""
    
    def __init__(self, db_path: str = "security_logs.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Inicializa a base de dados com tabelas"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela para entradas de log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user TEXT,
                event_type TEXT NOT NULL,
                port INTEGER,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                country_code TEXT,
                country_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela para estatísticas por IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                country_code TEXT,
                country_name TEXT,
                total_attempts INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                successful_attempts INTEGER DEFAULT 0,
                last_seen TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Índices para melhor performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON log_entries(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_service ON log_entries(service)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON log_entries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON log_entries(event_type)')
        
        conn.commit()
        conn.close()
    
    def insert_entry(self, entry: Dict) -> int:
        """Insere uma entrada de log"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO log_entries 
            (timestamp, service, ip_address, user, event_type, port, method, path, status_code, country_code, country_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('timestamp'),
            entry.get('service'),
            entry.get('ip'),
            entry.get('user'),
            entry.get('event_type'),
            entry.get('port'),
            entry.get('method'),
            entry.get('path'),
            entry.get('status_code'),
            entry.get('country_code'),
            entry.get('country_name')
        ))
        
        conn.commit()
        entry_id = cursor.lastrowid
        conn.close()
        
        return entry_id
    
    def insert_entries(self, entries: List[Dict]) -> int:
        """Insere múltiplas entradas"""
        
        count = 0
        for entry in entries:
            try:
                self.insert_entry(entry)
                count += 1
            except Exception as e:
                print(f"Erro ao inserir entrada: {e}")
        
        return count
    
    def update_ip_statistics(self, ip: str, country_code: str, country_name: str, event_type: str):
        """Atualiza estatísticas por IP"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verificar se IP existe
        cursor.execute('SELECT id FROM ip_statistics WHERE ip_address = ?', (ip,))
        exists = cursor.fetchone()
        
        if exists:
            if 'Failed' in event_type:
                cursor.execute('''
                    UPDATE ip_statistics 
                    SET failed_attempts = failed_attempts + 1,
                        total_attempts = total_attempts + 1,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE ip_address = ?
                ''', (ip,))
            else:
                cursor.execute('''
                    UPDATE ip_statistics 
                    SET successful_attempts = successful_attempts + 1,
                        total_attempts = total_attempts + 1,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE ip_address = ?
                ''', (ip,))
        else:
            failed = 1 if 'Failed' in event_type else 0
            successful = 0 if 'Failed' in event_type else 1
            
            cursor.execute('''
                INSERT INTO ip_statistics 
                (ip_address, country_code, country_name, total_attempts, failed_attempts, successful_attempts, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, country_code, country_name, failed, successful))
        
        conn.commit()
        conn.close()
    
    def get_all_entries(self, limit: int = None) -> List[Dict]:
        """Recupera todas as entradas"""
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = 'SELECT * FROM log_entries ORDER BY timestamp DESC'
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        entries = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return entries
    
    def get_entries_by_service(self, service: str) -> List[Dict]:
        """Recupera entradas por serviço"""
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM log_entries WHERE service = ? ORDER BY timestamp DESC', (service,))
        entries = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return entries
    
    def get_entries_by_country(self, country_code: str) -> List[Dict]:
        """Recupera entradas por país"""
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM log_entries WHERE country_code = ? ORDER BY timestamp DESC', (country_code,))
        entries = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return entries
    
    def get_top_ips(self, limit: int = 10) -> List[Dict]:
        """Recupera IPs com mais tentativas"""
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM ip_statistics 
            ORDER BY total_attempts DESC 
            LIMIT ?
        ''', (limit,))
        
        entries = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return entries
    
    def get_top_countries(self, limit: int = 10) -> List[Dict]:
        """Recupera países com mais tentativas"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT country_name, country_code, COUNT(*) as count, SUM(CASE WHEN event_type LIKE '%Failed%' THEN 1 ELSE 0 END) as failed
            FROM log_entries 
            GROUP BY country_code 
            ORDER BY count DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        entries = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        
        return entries
    
    def get_statistics(self) -> Dict:
        """Recupera estatísticas gerais"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total de entradas
        cursor.execute('SELECT COUNT(*) as total FROM log_entries')
        total = cursor.fetchone()[0]
        
        # Por serviço
        cursor.execute('SELECT service, COUNT(*) as count FROM log_entries GROUP BY service')
        by_service = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Por evento
        cursor.execute('SELECT event_type, COUNT(*) as count FROM log_entries GROUP BY event_type')
        by_event = {row[0]: row[1] for row in cursor.fetchall()}
        
        # IPs únicos
        cursor.execute('SELECT COUNT(DISTINCT ip_address) as unique_ips FROM log_entries')
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_entries': total,
            'unique_ips': unique_ips,
            'by_service': by_service,
            'by_event': by_event
        }
    
    def clear_all(self):
        """Limpa todas as tabelas (cuidado!)"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM log_entries')
        cursor.execute('DELETE FROM ip_statistics')
        
        conn.commit()
        conn.close()
