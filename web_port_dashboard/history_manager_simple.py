"""Gestionnaire d'historique simplifié utilisant des fichiers JSON"""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("cerbere.history")


class HistoryManager:
    """Gère l'historisation des snapshots et des alertes via des fichiers JSON.

    Toutes les écritures sont atomiques (fichier temporaire + os.replace) et
    sérialisées par un verrou : ce fichier est sollicité depuis plusieurs
    threads (event loop FastAPI, DnsSinkholeWorker, moniteur d'intrusion,
    handlers HTTP). Sans cela, deux écritures entrelacées peuvent tronquer
    alerts.json — le systray lirait alors une liste vide, réinitialiserait
    sa déduplication sur zéro clé, et rejouerait jusqu'à 50 notifications
    Windows au poll suivant (tempête de balloons au redémarrage).
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        if base_dir is None:
            import cerbere_paths as _paths
            base_dir = _paths.state_dir()

        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.base_dir / "history.json"
        self.alerts_file = self.base_dir / "alerts.json"

    @staticmethod
    def _write_json_atomic(path: Path, data: Any) -> None:
        """Écriture JSON atomique : tmp + os.replace (jamais de fichier tronqué)."""
        tmp = Path(str(path) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    @staticmethod
    def _read_json(path: Path, default):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError) as e:
            # Fichier corrompu ≠ fichier vide : on logue pour le diagnostic
            # au lieu de renvoyer silencieusement une liste vide.
            logger.warning("Fichier d'état corrompu %s : %s", path.name, e)
            return default

    def save_snapshot(self, data: Dict[str, Any]) -> None:
        """Sauvegarde un snapshot dans l'historique."""
        try:
            with _LOCK:
                history = []
                if self.history_file.exists():
                    history = self._read_json(self.history_file, [])

                history.append({
                    'timestamp': data.get('timestamp', datetime.now().isoformat()),
                    'risk_score': data.get('risk_score', 0),
                    'ports': data.get('ports', [])
                })

                history = history[-100:]
                self._write_json_atomic(self.history_file, history)

        except Exception as e:
            logger.error("Erreur save_snapshot: %s", e)

    def save_alert(self, risk_score: int, message: str) -> None:
        """Sauvegarde une alerte."""
        try:
            with _LOCK:
                alerts = []
                if self.alerts_file.exists():
                    alerts = self._read_json(self.alerts_file, [])

                alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'risk_score': risk_score,
                    'message': message
                })

                # Garder les 200 dernières (le bruit ne doit pas évincer les critiques)
                alerts = alerts[-200:]
                self._write_json_atomic(self.alerts_file, alerts)

        except Exception as e:
            logger.error("Erreur save_alert: %s", e)

    def delete_alert(self, timestamp: str, message: str) -> bool:
        """Supprime la première entrée d'alerte dont timestamp et message correspondent."""
        try:
            with _LOCK:
                if not self.alerts_file.exists():
                    return False

                alerts = self._read_json(self.alerts_file, None)
                if not isinstance(alerts, list):
                    return False

                found_idx = -1
                for idx, item in enumerate(alerts):
                    if isinstance(item, dict) and item.get('timestamp') == timestamp and item.get('message') == message:
                        found_idx = idx
                        break

                if found_idx == -1:
                    return False

                alerts.pop(found_idx)
                self._write_json_atomic(self.alerts_file, alerts)
                return True
        except Exception as e:
            logger.error("Erreur delete_alert: %s", e)
            return False

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retourne l'historique des snapshots."""
        try:
            if not self.history_file.exists():
                return []

            history = self._read_json(self.history_file, [])
            return list(reversed(history))[:limit]

        except Exception as e:
            logger.error("Erreur get_history: %s", e)
            return []

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retourne l'historique des alertes."""
        try:
            if not self.alerts_file.exists():
                return []

            alerts = self._read_json(self.alerts_file, [])
            return list(reversed(alerts))[:limit]

        except Exception as e:
            logger.error("Erreur get_alerts: %s", e)
            return []


# Verrou partagé par toutes les instances HistoryManager : plusieurs instances
# coexistent (scan loop, callbacks DNS/intrusion, handlers HTTP) et écrivent
# dans les mêmes fichiers d'état.
_LOCK = threading.Lock()
