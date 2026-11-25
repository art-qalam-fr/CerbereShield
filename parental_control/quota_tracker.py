"""Suivi des quotas quotidiens d'usage (mode « quota » du contrôle parental).

Compte le « temps actif » par domaine/catégorie : une minute compte si au moins
une requête DNS vers la cible a été observée pendant cette minute. C'est une
approximation honnête (le DNS voit des requêtes, pas du temps d'écran) —
documentée dans l'aide.

Persistance : web_port_dashboard/state/quota_usage.json
    {"YYYY-MM-DD": {"<clé règle>": ["HH:MM", "HH:MM", ...]}}
Le reset « à minuit » est naturel : chaque jour a sa propre entrée ; les jours
précédents sont purgés au chargement (on ne garde qu'aujourd'hui).
"""

import json
import logging
import os
import threading
from datetime import datetime
from typing import Callable, Dict, Optional

logger = logging.getLogger("parental_control.quota_tracker")


class QuotaTracker:
    """Compteur de minutes actives par clé de règle, persisté par jour."""

    def __init__(
        self,
        state_dir: str,
        clock: Optional[Callable[[], datetime]] = None,
        max_minutes_per_day: int = 1440,
    ):
        self._file = os.path.join(state_dir, "quota_usage.json")
        self._clock = clock or datetime.now
        self._max = max_minutes_per_day
        self._lock = threading.Lock()
        self._usage: Dict[str, Dict[str, list]] = self._load()

    def _load(self) -> Dict[str, Dict[str, list]]:
        if not os.path.isfile(self._file):
            return {}
        try:
            data = json.loads(open(self._file, "r", encoding="utf-8").read() or "{}")
            if not isinstance(data, dict):
                return {}
            today = self._clock().strftime("%Y-%m-%d")
            # Ne garder que les dates récentes (purge des jours anciens)
            return {
                d: {k: list(v) for k, v in keys.items() if isinstance(v, list)}
                for d, keys in data.items()
                if isinstance(d, str) and isinstance(keys, dict) and d >= today
            }
        except Exception as e:
            logger.debug("Impossible de charger quota_usage.json: %s", e)
            return {}

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._file), exist_ok=True)
            tmp = self._file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._usage, f)
            os.replace(tmp, self._file)
        except Exception as e:
            logger.debug("Impossible de sauvegarder quota_usage.json: %s", e)

    def note_activity(self, key: str) -> int:
        """Marque la minute courante comme active pour la clé.

        Returns:
            Nombre de minutes actives aujourd'hui pour cette clé.
        """
        now = self._clock()
        day, minute = now.strftime("%Y-%m-%d"), now.strftime("%H:%M")
        with self._lock:
            day_usage = self._usage.setdefault(day, {})
            minutes = day_usage.setdefault(key, [])
            if minute not in minutes and len(minutes) < self._max:
                minutes.append(minute)
                self._save()
            return len(minutes)

    def used_minutes(self, key: str) -> int:
        """Minutes actives aujourd'hui pour la clé (0 si aucune)."""
        day = self._clock().strftime("%Y-%m-%d")
        with self._lock:
            return len(self._usage.get(day, {}).get(key, []))

    def status(self) -> Dict[str, int]:
        """{clé: minutes utilisées} pour aujourd'hui — pour l'UI."""
        day = self._clock().strftime("%Y-%m-%d")
        with self._lock:
            return {k: len(v) for k, v in self._usage.get(day, {}).items()}
