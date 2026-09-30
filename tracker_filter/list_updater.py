"""Gestionnaire centralisé de mise à jour des listes de blocage.

Couvre les listes adblock (``tracker_filter.list_manager``) et les catégories
parentales/domestiques (``parental_control.lists_manager``), avec :

- ``update_all_lists`` : mise à jour ponctuelle de toutes les sources
  téléchargées, fail-open par liste (un échec n'empêche pas les autres) ;
- ``ListUpdateScheduler`` : planificateur non bloquant — vérification au
  démarrage puis cycle périodique (défaut : toutes les 24 h).
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("tracker_filter.list_updater")

_CONFIG_NAME = "update_scheduler.json"
_DEFAULT_INTERVAL_HOURS = 24.0
# Une liste dont le cache dépasse cet âge est considérée périmée au démarrage.
_STALE_THRESHOLD_HOURS = 24.0


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def update_all_lists(state_dir: str, include_parental: bool = True) -> Dict[str, Any]:
    """Met à jour toutes les listes téléchargées (adblock + parentales).

    Chaque source est indépendante : une erreur n'interrompt pas les autres.
    Ne lève jamais d'exception — le rapport contient les statuts par source.
    """
    report: Dict[str, Any] = {
        "started_at": _utcnow_iso(),
        "adblock": {},
        "parental": {},
        "errors": [],
    }
    started = time.monotonic()

    # --- Listes adblock ---
    try:
        from tracker_filter.list_manager import AdblockListManager

        adblock_mgr = AdblockListManager(state_dir=state_dir)
        report["adblock"] = adblock_mgr.refresh()
    except Exception as e:  # fail-open : module absent ou refresh planté
        logger.warning("Mise à jour adblock impossible : %s", e)
        report["errors"].append(f"adblock: {e}")

    # --- Catégories parentales/domestiques ---
    if include_parental:
        try:
            from parental_control.lists_manager import ListsManager

            lists_mgr = ListsManager(state_dir=state_dir)
            report["parental"] = lists_mgr.refresh()
        except Exception as e:
            logger.warning("Mise à jour des listes parentales impossible : %s", e)
            report["errors"].append(f"parental: {e}")

    report["duration_s"] = round(time.monotonic() - started, 2)
    report["finished_at"] = _utcnow_iso()
    return report


class ListUpdateScheduler:
    """Planifie les mises à jour des listes : démarrage + cycle périodique.

    Toutes les erreurs sont absorbées : le scheduler ne doit jamais faire
    tomber le backend. Configuration persistée dans
    ``state_dir/update_scheduler.json`` ({enabled, interval_hours}).
    """

    def __init__(
        self,
        state_dir: str,
        check_interval_hours: float = _DEFAULT_INTERVAL_HOURS,
        enabled: bool = True,
    ) -> None:
        self.state_dir = state_dir
        cfg = self._load_config(state_dir)
        self.interval_hours = float(
            cfg.get("interval_hours", check_interval_hours)
        )
        self.enabled = bool(cfg.get("enabled", enabled))
        self.last_run_report: Optional[Dict[str, Any]] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _load_config(state_dir: str) -> Dict[str, Any]:
        cfg_file = Path(state_dir) / _CONFIG_NAME
        try:
            if cfg_file.is_file():
                return json.loads(cfg_file.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if not self.enabled or self.is_running:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="list-update-scheduler", daemon=True
        )
        self._thread.start()
        logger.info(
            "Planificateur de listes démarré (intervalle %.1f h)", self.interval_hours
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _needs_update(self) -> bool:
        """True si au moins une liste activée est absente ou périmée."""
        try:
            from tracker_filter.list_manager import AdblockListManager

            status = AdblockListManager(state_dir=self.state_dir).status()
            for info in status.values():
                if not info.get("enabled"):
                    continue
                age = info.get("cache_age_hours")
                if info.get("status") in ("missing", "error") or age is None:
                    return True
                if age > _STALE_THRESHOLD_HOURS:
                    return True
        except Exception as e:
            logger.debug("Vérification des listes impossible : %s", e)
        return False

    def _run_once(self) -> None:
        try:
            self.last_run_report = update_all_lists(self.state_dir)
            n_err = len(self.last_run_report.get("errors", []))
            logger.info(
                "Mise à jour des listes terminée en %.1f s (%d erreur(s))",
                self.last_run_report.get("duration_s", 0),
                n_err,
            )
        except Exception as e:
            logger.warning("Cycle de mise à jour des listes échoué : %s", e)

    def _run_loop(self) -> None:
        try:
            if self._needs_update():
                self._run_once()
            while not self._stop.wait(self.interval_hours * 3600):
                self._run_once()
        except Exception as e:
            logger.warning("Planificateur de listes arrêté sur erreur : %s", e)
