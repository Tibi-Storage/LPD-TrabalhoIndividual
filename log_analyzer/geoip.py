"""
GeoIP Module - Identifica país e localização de IPs
"""

import socket
import json
from typing import Dict, Optional
from pathlib import Path


class GeoIPDatabase:
    """Gerencia dados GeoIP (usando maxminddb ou geoip2 se disponível)"""
    
    def __init__(self):
        self.cache = {}
        self._load_cache()
    
    def _load_cache(self):
        """Carrega cache de IPs já consultados"""
        cache_file = Path("geoip_cache.json")
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                self.cache = json.load(f)
    
    def _save_cache(self):
        """Salva cache de IPs"""
        with open("geoip_cache.json", 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def lookup(self, ip: str) -> Optional[Dict]:
        """
        Lookup de IP para país e localização
        Tenta usar geoip2 se disponível, senão usa reverse DNS
        """
        
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            import geoip2.database
            reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            response = reader.country(ip)
            
            result = {
                'ip': ip,
                'country': response.country.iso_code,
                'country_name': response.country.name,
                'continent': response.continent.code
            }
            
        except Exception:
            # Fallback: usar IP Stack API (free tier) ou apenas hostname
            result = self._fallback_lookup(ip)
        
        self.cache[ip] = result
        self._save_cache()
        return result
    
    def _fallback_lookup(self, ip: str) -> Dict:
        """Fallback usando reverse DNS e estimativa básica"""
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        
        # Estimativa básica baseada em ranges de IP conhecidos
        country = self._estimate_country_by_ip(ip)
        
        return {
            'ip': ip,
            'country': country,
            'country_name': self._country_code_to_name(country),
            'hostname': hostname
        }
    
    def _estimate_country_by_ip(self, ip: str) -> str:
        """Estimativa básica de país baseada em ranges conhecidos"""
        
        # Ranges conhecidos (simplificado)
        ranges = {
            'US': [
                (13, 16), (19, 23), (25, 25), (27, 27), (29, 29),
            ],
            'CN': [(1, 4), (27, 27), (36, 37), (39, 39), (42, 42)],
            'GB': [(2, 2)],
            'PT': [(85, 85)],
            'DE': [(3, 3), (31, 31)],
        }
        
        first_octet = int(ip.split('.')[0])
        
        for country, octets in ranges.items():
            for start, end in octets:
                if start <= first_octet <= end:
                    return country
        
        return "XX"  # Unknown
    
    def _country_code_to_name(self, code: str) -> str:
        """Converte código de país para nome"""
        
        countries = {
            'PT': 'Portugal',
            'US': 'United States',
            'CN': 'China',
            'GB': 'United Kingdom',
            'DE': 'Germany',
            'FR': 'France',
            'ES': 'Spain',
            'IT': 'Italy',
            'NL': 'Netherlands',
            'BR': 'Brazil',
            'IN': 'India',
            'RU': 'Russia',
            'JP': 'Japan',
        }
        
        return countries.get(code, f"Country {code}")
    
    def batch_lookup(self, ips: list) -> Dict[str, Dict]:
        """Faz lookup de múltiplos IPs"""
        
        results = {}
        for ip in set(ips):
            results[ip] = self.lookup(ip)
        
        return results
