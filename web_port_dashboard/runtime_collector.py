"""Collecte runtime pour le dashboard de ports
Réutilise NetworkCollector du module security_audit.collector
"""

from typing import Any, Dict
import sys
import os

# Ajout du chemin pour trouver security_audit
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    from security_audit.collector import NetworkCollector
except ImportError:
    # Fallback si security_audit n'est pas disponible
    class NetworkCollector:
        def __init__(self, config):
            self.config = config
        def collect_network_info(self):
            return {"ports": [], "timestamp": ""}


class RuntimeCollector:
    """Wrapper léger autour de NetworkCollector pour usage en continu"""

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        if config is None:
            config = {}
        # On force le debug à False par défaut pour le runtime
        cfg = {"debug": False, **config}
        self._collector = NetworkCollector(cfg)

    def get_snapshot(self) -> Dict[str, Any]:
        """Retourne un snapshot de l'état réseau courant compatible avec SecurityAnalyzer.

        Structure retournée (simplifiée) :
        {
            "ports": [...],
            "exposed_ports": [...],
            "total_ports": int,
            "total_exposed": int,
            "timestamp": str,
        }
        """

        return self._collector.collect_network_info()
