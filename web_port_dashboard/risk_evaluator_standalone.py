"""Évaluateur de risque pour le dashboard de ports - Version autonome"""

from typing import Any, Dict, List
import ipaddress


class RiskEvaluator:
    """Évalueur autonome pour les risques de sécurité"""

    def __init__(self, config: Dict[str, Any] | None = None, state_dir: str | None = None) -> None:
        if config is None:
            config = {}
        self.config = config
        self.critical_ports = set(config.get('critical_ports', [22, 80, 443, 3389, 3306, 5432]))
        self.allowed_ports = set(config.get('allowed_ports', []))

    def evaluate(self, network_data: Dict[str, Any], record_anomalies: bool = True) -> Dict[str, Any]:
        """Retourne un snapshot enrichi avec le score de risque et le niveau par port."""
        
        ports = network_data.get("ports", [])
        enriched_ports = []
        risk_score = 0
        
        for port in ports:
            port_num = port.get("port")
            is_exposed = self._is_exposed(port.get("local_address"))
            is_blocked = port.get("firewall_blocked", False)
            
            # Déterminer le niveau de risque
            if is_exposed and not is_blocked:  # Seulement si exposé ET non bloqué
                if port_num in self.critical_ports:
                    risk = "critical"
                    risk_score += 25
                elif port_num in self.allowed_ports:
                    risk = "authorized"
                    risk_score += 5
                else:
                    risk = "unexpected"
                    risk_score += 15
            else:
                # Port bloqué ou non exposé = autorisé
                risk = "authorized"
            
            enriched = dict(port)
            enriched["risk"] = risk
            enriched_ports.append(enriched)
        
        # Limiter le score à 100
        risk_score = min(100, risk_score)
        
        return {
            "timestamp": network_data.get("timestamp"),
            "risk_score": risk_score,
            "ports": enriched_ports,
            "total_ports": len(ports),
            "exposed_ports": len([p for p in enriched_ports if self._is_exposed(p.get("local_address")) and not p.get("firewall_blocked", False)]),
        }
    
    def _is_exposed(self, ip: str) -> bool:
        """Vérifie si l'IP est exposée (non-privée)"""
        if not ip:
            return False
        
        # IPs privées et locales
        private_ranges = [
            "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", 
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", 
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", 
            "172.29.", "172.30.", "172.31.", "169.254.", "::1"
        ]
        
        return not any(ip.startswith(prefix) for prefix in private_ranges)
