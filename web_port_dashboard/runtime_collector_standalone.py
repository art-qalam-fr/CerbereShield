"""Collecte runtime pour le dashboard de ports - Version autonome"""

from typing import Any, Dict, List
import psutil
import socket
from datetime import datetime
import ipaddress
import subprocess
import requests
import json
import os


class RuntimeCollector:
    """Collecteur autonome pour l'état réseau"""

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        if config is None:
            config = {}
        self.config = config
        self.critical_ports = set(config.get('critical_ports', [22, 80, 443, 3389, 3306, 5432]))
        self.allowed_ports = set(config.get('allowed_ports', []))

    def get_snapshot(self) -> Dict[str, Any]:
        """Retourne un snapshot de l'état réseau courant"""
        
        ports = []
        connections = psutil.net_connections(kind='inet')
        
        # Regrouper les ports par adresse locale
        port_info = {}
        
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                local_ip = conn.laddr.ip
                port = conn.laddr.port
                protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                
                key = (local_ip, port, protocol)
                if key not in port_info:
                    port_info[key] = {
                        'port': port,
                        'protocol': protocol,
                        'local_address': local_ip,
                        'local_ip': local_ip,  # Pour compatibilité
                        'ip': local_ip,        # Pour compatibilité
                        'remote_address': None,
                        'state': conn.status,
                        'process': None,
                        'pid': conn.pid,
                        'firewall_blocked': False  # Par défaut
                    }
                
                # Récupérer les infos du processus
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        port_info[key]['process'] = {
                            'name': process.name(),
                            'exe': process.exe()
                        }
                        port_info[key]['cmdline'] = ' '.join(process.cmdline())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        port_info[key]['process'] = {'name': 'Unknown', 'exe': ''}
                
                # Vérifier si le port est bloqué par le firewall (désactivé pour éviter les timeouts)
                # port_info[key]['firewall_blocked'] = self._is_firewall_blocked(port, protocol)
                port_info[key]['firewall_blocked'] = False  # Temporairement désactivé
        
        # Convertir en liste
        ports = list(port_info.values())
        
        # Marquer les ports comme bloqués selon l'état de protection
        try:
            # Lire l'état de protection (mis à jour par le script de durcissement)
            response = requests.get("http://127.0.0.1:4050/api/protection/state", timeout=1)
            if response.status_code == 200:
                protection_state = response.json()
                # Si la protection est active, on lit le dernier plan de durcissement
                if protection_state.get('enabled', False):
                    try:
                        import cerbere_paths as _paths
                        plan_file = str(_paths.plans_dir() / 'hardening_plan.json')
                    except ImportError:
                        plan_file = os.path.join(os.path.dirname(__file__), 'hardening_plan.json')
                    if os.path.exists(plan_file):
                        with open(plan_file, 'r') as f:
                            plan_data = json.load(f)
                            if plan_data.get('action') == 'harden':
                                blocked_ports = set()
                                for p in plan_data.get('ports', []):
                                    blocked_ports.add(f"{p['port']}|{p['protocol'].upper()}")
                                
                                for port in ports:
                                    port_key = f"{port['port']}|{port['protocol'].upper()}"
                                    port['firewall_blocked'] = port_key in blocked_ports
        except:
            pass  # En cas d'erreur, on laisse firewall_blocked à False
        
        # Évaluer les ports exposés
        exposed_ports = []
        for port in ports:
            ip = port['local_address']
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    exposed_ports.append(port)
            except:
                pass
        
        # Calculer le score de risque basé sur les ports exposés
        risk_score = 0
        for port in exposed_ports:
            if port['port'] in self.critical_ports:
                risk_score += 20
            else:
                risk_score += 10
        
        risk_score = min(100, risk_score)
        
        return {
            "ports": ports,
            "exposed_ports": exposed_ports,
            "total_ports": len(ports),
            "total_exposed": len(exposed_ports),
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat(),
        }
