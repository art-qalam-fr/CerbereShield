"""
Collecteur d'informations réseau
Récupère les ports ouverts, processus et connexions
"""

import subprocess
import re
import socket
import time
from typing import Dict, List, Any, Set, Tuple, Optional
import psutil


def _hidden_kwargs() -> Dict[str, Any]:
    """Kwargs subprocess : pas de fenêtre console quand l'app est fenêtrée."""
    if not hasattr(subprocess, "STARTUPINFO"):
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return {"startupinfo": si, "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


class NetworkCollector:
    """Classe pour collecter les informations réseau locales"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.debug = self.config.get('debug', False)
        self._firewall_cache: Optional[Dict[str, Any]] = None

    def invalidate_cache(self) -> None:
        """Invalide le cache des règles de pare-feu."""
        self._firewall_cache = None

    def collect_network_info(self) -> Dict[str, Any]:
        """
        Collecte les informations réseau principales
        Retourne un dictionnaire avec les données brutes
        """
        if self.debug:
            print("Démarrage de la collecte des informations réseau...")

        # Scan des ports avec psutil (PID en int)
        ports_data = self._scan_ports_psutil()

        # Collecte des informations sur les processus des ports détectés
        detected_pids = {p['pid'] for p in ports_data if p.get('pid') is not None}
        processes_data = self._get_processes_info(pids=detected_pids)

        # Association ports-processus
        enriched_ports = self._associate_ports_processes(ports_data, processes_data)

        # Marquage des ports bloqués par le firewall (règles Block_Port_*)
        firewall_blocked = self._get_firewall_blocked_ports()
        if firewall_blocked:
            for p in enriched_ports:
                key = (p.get('port'), (p.get('protocol') or '').lower())
                if key in firewall_blocked:
                    p['firewall_blocked'] = True

        # Détection de l'exposition externe (en ignorant les ports déjà bloqués par firewall)
        exposed_ports = self._detect_external_exposure(enriched_ports)

        result = {
            'ports': enriched_ports,
            'exposed_ports': exposed_ports,
            'total_ports': len(enriched_ports),
            'total_exposed': len(exposed_ports),
            'timestamp': self._get_timestamp()
        }

        if self.debug:
            print(f"Collecte terminée: {result['total_ports']} ports, {result['total_exposed']} exposés")

        return result

    def _scan_ports_psutil(self) -> List[Dict[str, Any]]:
        """Utilise psutil.net_connections(kind='inet') pour scanner les ports ouverts"""
        ports = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.type == socket.SOCK_STREAM:
                    # Ne garder que TCP en écoute
                    if conn.status != psutil.CONN_LISTEN and (not conn.status or conn.status.lower() != 'listening'):
                        continue
                    proto = 'tcp'
                    state = conn.status or 'LISTEN'
                elif conn.type == socket.SOCK_DGRAM:
                    proto = 'udp'
                    state = conn.status or ''
                else:
                    continue

                if not conn.laddr:
                    continue

                port_info = {
                    'protocol': proto,
                    'port': int(conn.laddr.port),
                    'local_ip': conn.laddr.ip,
                    'state': state,
                    'pid': int(conn.pid) if conn.pid is not None else None
                }
                ports.append(port_info)
        except Exception as e:
            if self.debug:
                print(f"Erreur lors du scan psutil: {e}")
            return []

        return ports

    def _scan_ports_netstat(self) -> List[Dict[str, Any]]:
        """Méthode conservée pour compatibilité : délègue au scan psutil."""
        return self._scan_ports_psutil()

    def _resolve_process_info(self, pid: Optional[int]) -> Dict[str, Any]:
        """Résout chaque PID via psutil.Process(pid) avec try/except :
        - nom='System' pour PID 4
        - nom='Idle' pour PID 0
        - sinon 'protected' en cas de NoSuchProcess / AccessDenied
        """
        if pid is None:
            return {'name': 'unknown', 'exe': '', 'cmdline': []}
        if pid == 0:
            return {'name': 'Idle', 'exe': '', 'cmdline': []}
        if pid == 4:
            return {'name': 'System', 'exe': '', 'cmdline': []}

        try:
            proc = psutil.Process(pid)
            try:
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = 'System' if pid == 4 else ('Idle' if pid == 0 else 'protected')
            except Exception:
                name = 'unknown'

            exe = ''
            try:
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                exe = ''

            cmdline = []
            try:
                cmdline = proc.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                cmdline = []

            return {
                'name': name or 'unknown',
                'exe': exe,
                'cmdline': cmdline
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            if pid == 4:
                return {'name': 'System', 'exe': '', 'cmdline': []}
            elif pid == 0:
                return {'name': 'Idle', 'exe': '', 'cmdline': []}
            else:
                return {'name': 'protected', 'exe': '', 'cmdline': []}
        except Exception:
            return {'name': 'unknown', 'exe': '', 'cmdline': []}

    def _get_processes_info(self, pids: Any = None) -> Dict[int, Dict[str, Any]]:
        """Récupère les informations sur les processus en cours"""
        processes: Dict[int, Dict[str, Any]] = {}
        if pids is not None:
            for pid in pids:
                if pid is not None:
                    processes[pid] = self._resolve_process_info(pid)
            return processes

        processes[0] = {'name': 'Idle', 'exe': '', 'cmdline': []}
        processes[4] = {'name': 'System', 'exe': '', 'cmdline': []}

        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    info = proc.info
                    pid = info['pid']
                    if pid is None:
                        continue
                    name = info.get('name')
                    if not name:
                        name = 'System' if pid == 4 else ('Idle' if pid == 0 else 'unknown')
                    processes[pid] = {
                        'name': name,
                        'exe': info.get('exe') or '',
                        'cmdline': info.get('cmdline') or []
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    if proc.pid == 4:
                        processes[4] = {'name': 'System', 'exe': '', 'cmdline': []}
                    elif proc.pid == 0:
                        processes[0] = {'name': 'Idle', 'exe': '', 'cmdline': []}
                    else:
                        processes[proc.pid] = {'name': 'protected', 'exe': '', 'cmdline': []}
                    continue
        except Exception as e:
            if self.debug:
                print(f"Erreur lors de la récupération des processus: {e}")

        return processes

    def _associate_ports_processes(self, ports: List[Dict], processes: Dict = None) -> List[Dict]:
        """Associe les ports aux processus correspondants"""
        if processes is None:
            processes = {}
        enriched = []
        for port in ports:
            pid = port.get('pid')
            if pid is not None:
                if pid in processes:
                    port['process'] = processes[pid]
                else:
                    proc_info = self._resolve_process_info(pid)
                    processes[pid] = proc_info
                    port['process'] = proc_info
            else:
                port['process'] = {'name': 'unknown', 'exe': '', 'cmdline': []}
            enriched.append(port)
        return enriched

    def _get_firewall_blocked_ports(self) -> Set[Tuple[int, str]]:
        """Retourne l'ensemble des ports bloqués par des règles Block_Port_XXX.

        On s'appuie sur la convention de nommage créée par le script PowerShell
        security_hardening.ps1 : Block_Port_<PORT>_<PROTO>.
        Un cache {rules, timestamp} est conservé pendant 300 secondes pour éviter
        de lancer un sous-processus PowerShell à chaque scan.
        """
        now = time.time()
        if self._firewall_cache is not None:
            cached_time = self._firewall_cache.get('timestamp', 0)
            if (now - cached_time) <= 300:
                return set(self._firewall_cache.get('rules', set()))

        blocked: Set[Tuple[int, str]] = set()
        try:
            result = subprocess.run(
                [
                    'powershell',
                    '-Command',
                    "Get-NetFirewallRule -DisplayName 'Block_Port_*' | Select-Object -ExpandProperty DisplayName",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                **_hidden_kwargs(),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    name = line.strip()
                    if not name:
                        continue
                    m = re.match(r"Block_Port_(\d+)_([A-Za-z]+)", name)
                    if not m:
                        continue
                    port = int(m.group(1))
                    proto = m.group(2).lower()
                    blocked.add((port, proto))

            self._firewall_cache = {
                'rules': blocked,
                'timestamp': now
            }
            return set(blocked)
        except Exception:
            if self._firewall_cache is not None:
                return set(self._firewall_cache.get('rules', set()))
            self._firewall_cache = {
                'rules': blocked,
                'timestamp': now
            }
            return blocked

    def _detect_external_exposure(self, ports: List[Dict]) -> List[Dict]:
        """Détecte les ports exposés sur 0.0.0.0 ou toutes les interfaces"""
        exposed = []
        for port in ports:
            # Si le port est déjà explicitement bloqué par le firewall, on ne le
            # considère plus comme exposé pour le calcul du score.
            if port.get('firewall_blocked'):
                continue
            ip = port.get('local_ip', '')
            # 0.0.0.0 signifie écoute sur toutes les interfaces
            if ip in ['0.0.0.0', '*', '::']:
                exposed.append(port)
        return exposed

    def _get_timestamp(self) -> str:
        """Retourne un timestamp pour les données"""
        from datetime import datetime
        return datetime.now().isoformat()
