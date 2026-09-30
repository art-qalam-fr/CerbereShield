"""Évaluation de risque pour le dashboard de ports.

Réutilise SecurityAnalyzer pour calculer :
- un score de risque global
- le statut de risque par port (critical / unexpected / authorized)
"""

import os
from typing import Any, Dict, List, Set
import sys
import os

# Ajout du chemin pour trouver security_audit
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    from security_audit.analyzer import SecurityAnalyzer
except ImportError:
    # Fallback si security_audit n'est pas disponible
    class SecurityAnalyzer:
        def __init__(self, config):
            self.config = config
        def analyze(self, data):
            return {"risk_score": 0, "ports": []}


class RiskEvaluator:
    """Évalue le risque à partir des données réseau collectées."""

    SYSTEM_PROCESSES: Set[str] = {
        "system",
        "idle",
        "protected",
        "unknown",
        "svchost.exe",
        "system idle process",
    }

    SUSPECT_BINARIES: Set[str] = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "nc.exe",
        "ncat.exe",
        "netcat.exe",
        "python.exe",
    }

    def __init__(self, config: Dict[str, Any] | None = None, state_dir: str | None = None) -> None:
        if config is None:
            config = {}
        self._config = config
        # On laisse passer critical_ports / allowed_ports depuis la config
        self._analyzer = SecurityAnalyzer(config)

        # Ports critiques (alerte renforcée si processus inhabituel écoute dessus)
        self._critical_ports: Set[int] = set(
            config.get("critical_ports", [22, 80, 443, 3389, 3306, 5432])
        )
        # Processus explicitement autorisés (minuscules) + processus système
        self._allowed_processes: Set[str] = {
            name.lower() for name in config.get("allowed_processes", [])
        } | self.SYSTEM_PROCESSES
        # PID du backend lui-même (python.exe écoute sur 4050) — jamais une anomalie
        self._own_pid: int = os.getpid()
        # Déduplication persistante : une anomalie n'alerte qu'une fois,
        # y compris après un redémarrage du backend.
        self._anomalies_file = (
            os.path.join(state_dir, "reported_anomalies.json") if state_dir else None
        )
        self._reported_anomalies: Set[tuple] = self._load_reported_anomalies()

    def _load_reported_anomalies(self) -> Set[tuple]:
        if not self._anomalies_file or not os.path.isfile(self._anomalies_file):
            return set()
        try:
            import json as _json
            data = _json.loads(open(self._anomalies_file, "r", encoding="utf-8").read() or "[]")
            return {tuple(x) for x in data if isinstance(x, list)}
        except Exception:
            return set()

    def _save_reported_anomalies(self) -> None:
        if not self._anomalies_file:
            return
        try:
            import json as _json
            os.makedirs(os.path.dirname(self._anomalies_file), exist_ok=True)
            tmp = self._anomalies_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump([list(t) for t in self._reported_anomalies], f)
            os.replace(tmp, self._anomalies_file)
        except Exception:
            pass

    def evaluate(
        self, network_data: Dict[str, Any], record_anomalies: bool = True
    ) -> Dict[str, Any]:
        """Retourne un snapshot enrichi avec le score de risque et le niveau par port.

        Args:
            record_anomalies: quand False (pre-scan de démarrage), les anomalies
                détectées sont retournées dans ``alerts`` mais NE SONT PAS
                marquées comme rapportées — sinon une anomalie présente au boot
                serait dedupliquée à jamais sans jamais avoir été notifiée.

        Sortie typique :
        {
            "timestamp": str,
            "risk_score": int,
            "ports": [
                {
                    ... données de NetworkCollector ...,
                    "risk": "critical" | "unexpected" | "authorized",
                },
                ...
            ],
        }
        """

        analysis = self._analyzer.analyze_risks(network_data)

        # Indexer les ports critiques / inattendus par (port, protocol, local_ip)
        def _key(p: Dict[str, Any]) -> tuple:
            return (
                p.get("port"),
                (p.get("protocol") or p.get("proto")),
                p.get("local_ip") or p.get("ip"),
            )

        critical_map = {_key(p): p for p in analysis.get("critical_exposed", [])}
        unexpected_map = {_key(p): p for p in analysis.get("unexpected_exposed", [])}

        enriched_ports: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []

        for port in network_data.get("ports", []):
            k = _key(port)
            if k in critical_map:
                risk = "critical"
            elif k in unexpected_map:
                risk = "unexpected"
            else:
                risk = "authorized"

            enriched = dict(port)
            enriched["risk"] = risk

            # Détection d'anomalie au niveau processus (indépendante du score global)
            state = (port.get("state") or port.get("status") or "").upper()
            if state in {"LISTEN", "LISTENING"}:
                proc_info = port.get("process") or {}
                proc_name = (
                    proc_info.get("name")
                    or port.get("process_name")
                    or proc_info.get("process_name")
                )
                pid = proc_info.get("pid") or port.get("pid")
                port_num = port.get("port")
                proto = port.get("protocol") or port.get("proto")
                local_ip = port.get("local_ip") or port.get("ip") or ""

                if risk == "unexpected" and pid != self._own_pid:
                    unexpected_key = ("unexpected_port", port_num, proto, local_ip)
                    if unexpected_key not in self._reported_anomalies:
                        if record_anomalies:
                            self._reported_anomalies.add(unexpected_key)
                            self._save_reported_anomalies()
                        alerts.append(
                            {
                                "type": "insecure_port",
                                "severity": "warning",
                                "message": f"Port {port_num}/{proto} non securise expose par {proc_name or 'processus inconnu'}",
                                "port": port_num,
                                "process": proc_name,
                                "pid": pid,
                            }
                        )

                if pid == self._own_pid:
                    enriched_ports.append(enriched)
                    continue

                if proc_name and isinstance(proc_name, str):
                    name_lc = proc_name.lower()
                    if name_lc not in self._allowed_processes:
                        local_ip_str = local_ip.strip()
                        is_loopback = local_ip_str.startswith("127.") or local_ip_str in {"::1", "localhost"}
                        is_critical_port = isinstance(port_num, int) and port_num in self._critical_ports
                        is_suspect_binary = name_lc in self.SUSPECT_BINARIES
                        # Binaire suspect en loopback pur = IPC local (MCP, outils dev) → pas d'alerte.
                        # Exposé au réseau (0.0.0.0, ::, IP externe) ou port critique → alerte.
                        if is_critical_port or (is_suspect_binary and not is_loopback):
                            severity = "critical" if is_critical_port else "warning"
                            enriched["process_anomaly"] = True
                            anomaly_key = (name_lc, port_num)
                            if anomaly_key not in self._reported_anomalies:
                                if record_anomalies:
                                    self._reported_anomalies.add(anomaly_key)
                                    self._save_reported_anomalies()
                                alerts.append(
                                {
                                    "type": "process_anomaly",
                                    "severity": severity,
                                    "message": f"Processus {proc_name} (PID {pid}) écoute sur le port {port_num}/{port.get('protocol') or port.get('proto')}",
                                    "port": port_num,
                                    "process": proc_name,
                                    "pid": pid,
                                }
                            )

            enriched_ports.append(enriched)

        return {
            "timestamp": network_data.get("timestamp"),
            "risk_score": analysis.get("risk_score", 0),
            "ports": enriched_ports,
            "alerts": alerts,
        }
