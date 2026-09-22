#!/usr/bin/env python3
"""
Module de Détection d'Intrusion pour Security Shield
Analyse les logs Windows et bloque les IP malveillantes
"""

import ipaddress
import os
import sys
import time
import json
import sqlite3
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import logging
from logging.handlers import RotatingFileHandler
import re

# Chemins centralisés (source / PyInstaller frozen)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cerbere_paths as _paths

# Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            str(_paths.logs_dir() / 'intrusion_detection.log'),
            maxBytes=5*1024*1024,
            backupCount=3
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Événement de sécurité détecté"""
    timestamp: datetime
    event_type: str
    source_ip: str
    target_service: str
    details: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

@dataclass
class BannedIP:
    """IP bannie avec détails"""
    ip_address: str
    ban_time: datetime
    unban_time: datetime
    reason: str
    attempt_count: int
    source_events: List[str]

class IntrusionDetector:
    """Détecteur d'intrusion principal"""
    
    def __init__(self, config_path: str = None):
        # Par défaut, chercher la config dans config/intrusion_detection.json
        if config_path is None:
            config_path = str(_paths.bundled_file('config', 'intrusion_detection.json'))
        self._config_path = config_path
        self.config = self._load_config(config_path)

        # Chemin absolu pour la base de données (logs/ — inscriptible)
        base_dir = str(_paths.data_root())
        db_cfg = self.config.get('database_path', 'logs/intrusion_detection.db')
        self.db_path = db_cfg if os.path.isabs(db_cfg) else os.path.join(base_dir, db_cfg)
        self.banned_ips = {}
        self.security_events = deque(maxlen=10000)
        self.whitelist = set(self.config.get('whitelist', ['127.0.0.1', '::1']))
        self.running = False
        self.monitor_thread = None
        self.alert_callback = None
        
        # Seuils de détection
        self.thresholds = {
            'failed_login': self.config.get('failed_login_threshold', 5),
            'failed_login_window': self.config.get('failed_login_window', 300),  # 5 minutes
            'port_scan_threshold': self.config.get('port_scan_threshold', 10),
            'port_scan_window': self.config.get('port_scan_window', 60),  # 1 minute
            'ban_duration': self.config.get('ban_duration', 3600)  # 1 hour
        }
        
        self._init_database()
        self._load_active_bans()
        
    def _load_config(self, config_path: str = None) -> dict:
        """Charger la configuration"""
        default_config = {
            "database_path": "logs/intrusion_detection.db",
            "whitelist": ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
            "failed_login_threshold": 5,
            "failed_login_window": 300,
            "port_scan_threshold": 10,
            "port_scan_window": 60,
            "ban_duration": 3600,
            "log_sources": ["Security", "System", "Application"],
            "monitored_services": ["SSH", "RDP", "FTP", "HTTP", "HTTPS", "SMB"]
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Impossible de charger la config: {e}")
        
        return default_config
    
    def _init_database(self):
        """Initialiser la base de données"""
        db_dir = os.path.dirname(self.db_path)
        os.makedirs(db_dir, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des événements
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_service TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL
            )
        ''')
        
        # Table des IP bannies
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                ban_time TEXT NOT NULL,
                unban_time TEXT NOT NULL,
                reason TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Table des statistiques
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                total_events INTEGER NOT NULL,
                banned_ips_count INTEGER NOT NULL,
                top_attack_types TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Base de données de détection d'intrusion initialisée")

    def _load_active_bans(self):
        """Recharger les bannissements actifs depuis la base de données"""
        if not os.path.exists(self.db_path):
            return

        now = datetime.now()
        expired_ips = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT ip_address, ban_time, unban_time, reason, attempt_count '
                'FROM banned_ips WHERE is_active = 1'
            )
            rows = cursor.fetchall()
            for ip, ban_time_str, unban_time_str, reason, attempt_count in rows:
                try:
                    ban_time = datetime.fromisoformat(ban_time_str)
                    unban_time = datetime.fromisoformat(unban_time_str)
                    if unban_time.tzinfo is not None:
                        unban_time = unban_time.replace(tzinfo=None)
                    if ban_time.tzinfo is not None:
                        ban_time = ban_time.replace(tzinfo=None)
                    if unban_time > now:
                        self.banned_ips[ip] = BannedIP(
                            ip_address=ip,
                            ban_time=ban_time,
                            unban_time=unban_time,
                            reason=reason,
                            attempt_count=attempt_count,
                            source_events=[]
                        )
                    else:
                        expired_ips.append(ip)
                except Exception as e:
                    logger.warning(f"Erreur parsing date ban pour {ip}: {e}")

            if expired_ips:
                cursor.executemany(
                    'UPDATE banned_ips SET is_active = 0 WHERE ip_address = ?',
                    [(ip,) for ip in expired_ips]
                )
                conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Erreur lors du rechargement des bans actifs: {e}")

    def is_banned(self, ip: str) -> bool:
        """Vérifier si une IP est bannie"""
        return ip in self.banned_ips
    
    def get_windows_security_logs(self, hours_back: int = 1) -> List[SecurityEvent]:
        """Récupérer les logs de sécurité Windows"""
        events = []
        
        try:
            # Commande PowerShell pour récupérer les logs de sécurité - optimisée
            ps_command = f'''
            Get-WinEvent -FilterHashtable @{{
                LogName='Security';
                StartTime=(Get-Date).AddHours(-{hours_back});
                Level=2,3  # Warning et Error seulement
            }} | Where-Object {{ $_.Id -in 4625,4624,4768,4769,5061 }} | Select-Object -First 10 TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10,  # Timeout réduit
                **_paths.hidden_subprocess_kwargs(),
            )
            
            if result.returncode == 0:
                logs_data = json.loads(result.stdout)
                if not isinstance(logs_data, list):
                    logs_data = [logs_data]
                
                for log_entry in logs_data:
                    event = self._parse_security_event(log_entry)
                    if event:
                        events.append(event)
                        
        except subprocess.TimeoutExpired:
            logger.error("Timeout lors de la récupération des logs")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des logs: {e}")
        
        return events
    
    def _parse_security_event(self, log_entry: dict) -> Optional[SecurityEvent]:
        """Parser un événement de sécurité Windows"""
        try:
            timestamp = datetime.fromisoformat(log_entry['TimeCreated'].replace('Z', '+00:00'))
            event_id = log_entry['Id']
            message = log_entry['Message']
            
            # Extraire l'IP source du message
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            source_ip = ip_match.group(1) if ip_match else "Unknown"
            
            # Classifier l'événement
            event_type, severity, service = self._classify_event(event_id, message)
            
            return SecurityEvent(
                timestamp=timestamp,
                event_type=event_type,
                source_ip=source_ip,
                target_service=service,
                details=message[:200],  # Limiter la taille
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Erreur parsing événement: {e}")
            return None
    
    def _classify_event(self, event_id: int, message: str) -> Tuple[str, str, str]:
        """Classifier un événement de sécurité"""
        
        # Échecs de connexion
        if event_id in [4625, 4771, 4768, 4770]:
            if "RDP" in message or "Remote Desktop" in message:
                return "FAILED_LOGIN_RDP", "HIGH", "RDP"
            elif "SSH" in message:
                return "FAILED_LOGIN_SSH", "HIGH", "SSH"
            elif "FTP" in message:
                return "FAILED_LOGIN_FTP", "MEDIUM", "FTP"
            else:
                return "FAILED_LOGIN", "MEDIUM", "Unknown"
        
        # Succès de connexion
        elif event_id == 4624:
            return "SUCCESSFUL_LOGIN", "LOW", "Unknown"
        
        # Détection d'attaques
        elif event_id in [4626, 4648, 4769, 4776]:
            return "SUSPICIOUS_ACTIVITY", "MEDIUM", "Unknown"
        
        # Audit système
        elif event_id in [4672, 4673, 4674]:
            return "PRIVILEGE_USE", "MEDIUM", "System"
        
        # Événements réseau
        elif event_id in [5156, 5157]:
            return "NETWORK_CONNECTION", "LOW", "Network"
        
        else:
            return "UNKNOWN", "LOW", "Unknown"
    
    def detect_intrusions(self, events: List[SecurityEvent]):
        """Détecter les intrusions basées sur les événements"""
        
        # Grouper les événements par IP
        ip_events = defaultdict(list)
        for event in events:
            if event.source_ip != "Unknown" and not self._is_whitelisted(event.source_ip):
                ip_events[event.source_ip].append(event)
        
        # Analyser chaque IP
        for ip, ip_event_list in ip_events.items():
            self._analyze_ip_activity(ip, ip_event_list)
    
    def _analyze_ip_activity(self, ip: str, events: List[SecurityEvent]):
        """Analyser l'activité d'une IP spécifique"""
        
        # Compter les échecs de connexion récents
        now = datetime.now()
        failed_logins = [
            e for e in events 
            if "FAILED_LOGIN" in e.event_type 
            and (now - e.timestamp).total_seconds() < self.thresholds['failed_login_window']
        ]
        
        # Détecter les tentatives de force brute
        if len(failed_logins) >= self.thresholds['failed_login']:
            self._ban_ip(ip, f"Force brute attack: {len(failed_logins)} failed logins", failed_logins)
            return
        
        # Détecter les scans de ports
        recent_events = [
            e for e in events 
            if (now - e.timestamp).total_seconds() < self.thresholds['port_scan_window']
        ]
        
        if len(recent_events) >= self.thresholds['port_scan_threshold']:
            self._ban_ip(ip, f"Port scan detected: {len(recent_events)} events", recent_events)
    
    def _ban_ip(self, ip: str, reason: str, events: List[SecurityEvent]):
        """Bannir une IP via Windows Firewall"""
        
        if ip in self.banned_ips:
            return  # Déjà bannie
        
        try:
            # Créer la règle firewall
            rule_name = f"SecurityShield_Blocked_{ip.replace('.', '_')}"
            
            # Vérifier si la règle existe déjà
            check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            result = subprocess.run(check_cmd, capture_output=True, text=True, **_paths.hidden_subprocess_kwargs())
            
            if "No rules match" in result.stdout:
                # Créer la règle de blocage
                block_cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
                subprocess.run(block_cmd, check=True, **_paths.hidden_subprocess_kwargs())
                
                # Enregistrer le bannissement
                ban_time = datetime.now()
                unban_time = ban_time + timedelta(seconds=self.thresholds['ban_duration'])
                
                banned_ip = BannedIP(
                    ip_address=ip,
                    ban_time=ban_time,
                    unban_time=unban_time,
                    reason=reason,
                    attempt_count=len(events),
                    source_events=[str(e.timestamp) for e in events[:5]]
                )
                
                self.banned_ips[ip] = banned_ip
                self._save_banned_ip(banned_ip)
                
                logger.warning(f"IP {ip} bannie: {reason}")
                
                if self.alert_callback:
                    try:
                        self.alert_callback(90, 'Intrusion detectee : IP ' + ip + ' bannie - ' + reason)
                    except:
                        pass
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Erreur lors du bannissement de {ip}: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors du bannissement: {e}")
    
    def _save_banned_ip(self, banned_ip: BannedIP):
        """Sauvegarder une IP bannie en base de données"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO banned_ips 
            (ip_address, ban_time, unban_time, reason, attempt_count, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (
            banned_ip.ip_address,
            banned_ip.ban_time.isoformat(),
            banned_ip.unban_time.isoformat(),
            banned_ip.reason,
            banned_ip.attempt_count
        ))
        
        conn.commit()
        conn.close()
    
    def unban_expired_ips(self):
        """Débannir les IP dont le bannissement a expiré"""
        now = datetime.now()
        expired_ips = []
        
        for ip, banned_ip in list(self.banned_ips.items()):
            if now >= banned_ip.unban_time:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            try:
                # Supprimer la règle firewall
                rule_name = f"SecurityShield_Blocked_{ip.replace('.', '_')}"
                unblock_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(unblock_cmd, check=True, **_paths.hidden_subprocess_kwargs())
                
                # Marquer comme inactive en base
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('UPDATE banned_ips SET is_active = 0 WHERE ip_address = ?', (ip,))
                conn.commit()
                conn.close()
                
                del self.banned_ips[ip]
                logger.info(f"IP {ip} débannie")
                
            except Exception as e:
                logger.error(f"Erreur lors du débannissement de {ip}: {e}")
    
    def get_dashboard_data(self) -> dict:
        """Récupérer les données pour le tableau de bord"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Statistiques générales
        cursor.execute('''
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT source_ip) as unique_ips,
                COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_severity,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_severity
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        
        stats = cursor.fetchone()
        
        # IP actuellement bannies
        cursor.execute('SELECT COUNT(*) FROM banned_ips WHERE is_active = 1')
        banned_count = cursor.fetchone()[0]
        
        # Top 5 des types d'attaques
        cursor.execute('''
            SELECT event_type, COUNT(*) as count 
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY event_type 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        
        top_attacks = cursor.fetchall()
        
        # Événements récents
        cursor.execute('''
            SELECT timestamp, event_type, source_ip, severity, details
            FROM security_events 
            WHERE timestamp > datetime('now', '-6 hours')
            ORDER BY timestamp DESC 
            LIMIT 20
        ''')
        
        recent_events = cursor.fetchall()
        
        conn.close()
        
        return {
            'statistics': {
                'total_events': stats[0] or 0,
                'unique_ips': stats[1] or 0,
                'high_severity': stats[2] or 0,
                'critical_severity': stats[3] or 0,
                'banned_ips': banned_count
            },
            'top_attacks': [{'type': row[0], 'count': row[1]} for row in top_attacks],
            'recent_events': [
                {
                    'timestamp': row[0],
                    'type': row[1],
                    'source_ip': row[2],
                    'severity': row[3],
                    'details': row[4]
                }
                for row in recent_events
            ],
            'active_bans': len(self.banned_ips)
        }
    
    def get_banned_ips(self, limit: int = 50) -> List[dict]:
        """Récupérer la liste des IP bannies"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address, ban_time, unban_time, reason, attempt_count, is_active
            FROM banned_ips 
            ORDER BY ban_time DESC 
            LIMIT ?
        ''', (limit,))
        
        banned = []
        for row in cursor.fetchall():
            banned.append({
                'ip': row[0],
                'ban_time': row[1],
                'unban_time': row[2],
                'reason': row[3],
                'attempt_count': row[4],
                'active': bool(row[5])
            })
        
        conn.close()
        return banned
    
    def unban_ip(self, ip: str) -> bool:
        """Débannir manuellement une IP"""
        if ip in self.banned_ips:
            try:
                rule_name = f"SecurityShield_Blocked_{ip.replace('.', '_')}"
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], check=True, **_paths.hidden_subprocess_kwargs())
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('UPDATE banned_ips SET is_active = 0 WHERE ip_address = ?', (ip,))
                conn.commit()
                conn.close()
                
                del self.banned_ips[ip]
                logger.info(f"IP {ip} débannie manuellement")
                return True
            except Exception as e:
                logger.error(f"Erreur lors du débannissement de {ip}: {e}")
                return False
        return False
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Match exact ou appartenance à un réseau CIDR de la whitelist.

        La config par défaut contient des CIDR (192.168.0.0/16, 10.0.0.0/8…) :
        une comparaison de chaîne exacte ne les aurait jamais honorés,
        rendant bannissables toutes les IP du LAN."""
        if ip in self.whitelist:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.whitelist:
            if "/" not in entry:
                continue
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _save_whitelist_config(self):
        """Écrire self.config['whitelist'] dans self._config_path"""
        if not self._config_path:
            return
        try:
            self.config['whitelist'] = sorted(self.whitelist)
            config_dir = os.path.dirname(self._config_path)
            if config_dir:
                os.makedirs(config_dir, exist_ok=True)
            with open(self._config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la configuration: {e}")

    def add_to_whitelist(self, ip: str) -> bool:
        """Ajouter une IP à la whitelist"""
        self.whitelist.add(ip)
        self._save_whitelist_config()
        # Si l'IP est bannie, la débannir
        if ip in self.banned_ips:
            return self.unban_ip(ip)
        return True
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """Retirer une IP de la whitelist"""
        self.whitelist.discard(ip)
        self._save_whitelist_config()
        return True
    
    def get_whitelist(self) -> List[str]:
        """Récupérer la whitelist"""
        return list(self.whitelist)
    
    def start_monitoring(self):
        """Démarrer la surveillance en continu dans un thread séparé (non bloquant)"""
        if self.running:
            return
        self.running = True
        logger.info("Surveillance de détection d'intrusion démarrée")
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

    def _monitoring_loop(self):
        """Boucle interne de surveillance exécutée dans monitor_thread"""
        while self.running:
            try:
                # Récupérer les événements récents
                events = self.get_windows_security_logs(hours_back=1)
                
                # Détecter les intrusions
                self.detect_intrusions(events)
                
                # Nettoyer les bannissements expirés
                self.unban_expired_ips()
                
                # Pause de 30 secondes entre chaque scan pour réduire la charge
                for _ in range(30):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Erreur dans la boucle de surveillance: {e}")
                time.sleep(10)  # Pause en cas d'erreur plus longtemps en cas d'erreur
    
    def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Surveillance de détection d'intrusion arrêtée")

# Instance globale pour le module
_detector_instance = None

def get_detector() -> IntrusionDetector:
    """Récupérer l'instance globale du détecteur"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = IntrusionDetector()
    return _detector_instance

def start_intrusion_detection():
    """Démarrer le module de détection d'intrusion"""
    detector = get_detector()
    detector.start_monitoring()
    return detector

def stop_intrusion_detection():
    """Arrêter le module de détection d'intrusion"""
    detector = get_detector()
    detector.stop_monitoring()
