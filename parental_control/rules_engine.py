"""Moteur de règles du contrôle parental et du contrôle domestique.

Deux « scopes » de règles persistés dans
web_port_dashboard/state/parental_rules.json :

    {
      "parental": {
        "enabled": false,
        "categories": {"adult": {"mode": "blocked"},
                        "social_tiktok": {"mode": "quota", "quota_minutes": 120}},
        "domains": {"tiktok.com": {"mode": "window",
                                    "windows": [["17:00", "19:00"]]}}
      },
      "domestic": { "enabled": false,
                    "categories": {"payment": {"mode": "blocked"}},
                    "domains": {} }
    }

Modes : ``blocked`` (sinkhole permanent), ``window`` (autorisé dans les plages
HH:MM, bloqué sinon), ``quota`` (autorisé tant que le temps actif du jour est
sous ``quota_minutes``, bloqué ensuite — approximation DNS, cf. QuotaTracker).

Priorité : règle de domaine personnalisée > règle de catégorie. Un domaine
couvert par les deux scopes applique la règle la plus restrictive rencontrée
(blocked > window-denied > quota-exceeded > allow).
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from .quota_tracker import QuotaTracker

logger = logging.getLogger("parental_control.rules_engine")

SCOPES = ("parental", "domestic")
VALID_MODES = ("blocked", "window", "quota")

_DEFAULT_STATE = {
    scope: {"enabled": False, "categories": {}, "domains": {}} for scope in SCOPES
}


@dataclass
class Decision:
    """Résultat de l'évaluation d'une requête DNS."""

    blocked: bool
    scope: str = ""
    matched: str = ""          # domaine de liste ou règle custom ayant matché
    rule_key: str = ""         # "cat:adult" / "dom:tiktok.com"
    mode: str = ""
    reason: str = ""


def _hm_to_min(hm: str) -> Optional[int]:
    """'HH:MM' -> minutes depuis minuit, ou None si invalide."""
    try:
        h, m = hm.split(":")
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h * 60 + m
    except (ValueError, AttributeError):
        pass
    return None


def _suffix_candidates(domain: str) -> List[str]:
    parts = domain.split(".")
    if len(parts) <= 1:
        return [domain]
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


class RulesEngine:
    """Évalue les requêtes DNS contre les règles parentales/domestiques.

    Args:
        lists_manager: objet exposant ``get_domains(category) -> frozenset``.
        quota_tracker: QuotaTracker pour le mode « quota ».
        state_dir: dossier de persistance (web_port_dashboard/state).
        clock: injectable pour les tests (défaut datetime.now).
    """

    def __init__(
        self,
        lists_manager,
        quota_tracker: QuotaTracker,
        state_dir: str,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self._lists = lists_manager
        self._quota = quota_tracker
        self._file = os.path.join(state_dir, "parental_rules.json")
        self._clock = clock or datetime.now
        self._lock = threading.Lock()
        self._state = self._load()

    # ---------- persistance ----------

    def _load(self) -> dict:
        if not os.path.isfile(self._file):
            return json.loads(json.dumps(_DEFAULT_STATE))
        try:
            data = json.loads(open(self._file, "r", encoding="utf-8").read() or "{}")
        except Exception as e:
            logger.warning("parental_rules.json illisible, reset: %s", e)
            return json.loads(json.dumps(_DEFAULT_STATE))
        state = json.loads(json.dumps(_DEFAULT_STATE))
        for scope in SCOPES:
            s = data.get(scope)
            if isinstance(s, dict):
                state[scope]["enabled"] = bool(s.get("enabled", False))
                state[scope]["categories"] = s.get("categories") or {}
                state[scope]["domains"] = s.get("domains") or {}
        return state

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._file), exist_ok=True)
            tmp = self._file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(tmp, self._file)
        except Exception as e:
            logger.error("Impossible de sauvegarder parental_rules.json: %s", e)

    # ---------- gestion des règles (appelée par l'API, déjà protégée PIN) ----------

    def get_rules(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def set_scope_enabled(self, scope: str, enabled: bool) -> None:
        if scope not in SCOPES:
            raise ValueError(f"scope inconnu: {scope}")
        with self._lock:
            self._state[scope]["enabled"] = bool(enabled)
            self._save()
        logger.info("Contrôle %s %s.", scope, "activé" if enabled else "désactivé")

    def is_enabled(self, scope: str) -> bool:
        with self._lock:
            return bool(self._state.get(scope, {}).get("enabled"))

    def update_scope(self, scope: str, categories: dict, domains: dict) -> None:
        """Remplace les règles d'un scope (validation des modes/champs)."""
        if scope not in SCOPES:
            raise ValueError(f"scope inconnu: {scope}")
        for key, rule in list(categories.items()) + list(domains.items()):
            if not isinstance(rule, dict) or rule.get("mode") not in VALID_MODES:
                raise ValueError(f"règle invalide pour {key!r}")
            if rule["mode"] == "quota" and not isinstance(rule.get("quota_minutes"), int):
                raise ValueError(f"quota_minutes manquant pour {key!r}")
            if rule["mode"] == "window":
                wins = rule.get("windows") or []
                for w in wins:
                    if (
                        not isinstance(w, (list, tuple)) or len(w) != 2
                        or _hm_to_min(w[0]) is None or _hm_to_min(w[1]) is None
                    ):
                        raise ValueError(f"fenêtre invalide pour {key!r}")
        with self._lock:
            self._state[scope]["categories"] = categories
            self._state[scope]["domains"] = domains
            self._save()

    # ---------- évaluation ----------

    def decide(self, domain: str) -> Decision:
        """Décide si la requête vers ``domain`` doit être bloquée.

        Appelée par le sinkhole à chaque requête. Pour le mode « quota »,
        une décision d'autorisation enregistre la minute comme active.
        """
        domain = domain.lower().rstrip(".")
        candidates = _suffix_candidates(domain)
        now = self._clock()

        # Lecture sans copie : update_scope remplace les dicts en entier (swap
        # atomique sous GIL), jamais de mutation en place — le snapshot reste
        # cohérent pour toute la durée de l'évaluation.
        snapshot = self._state

        # On évalue TOUTES les règles qui matchent (les deux scopes) puis on
        # retient la plus restrictive : un « autorisé » parental ne doit pas
        # neutraliser un « bloqué » domestique (ex. domaine à la fois dans une
        # fenêtre horaire et dans la liste paiement).
        matched_rules: List[Tuple[str, str, str, dict]] = []  # scope, key, matched, rule
        for scope in SCOPES:
            sc = snapshot[scope]
            if not sc["enabled"]:
                continue
            # Règle de domaine personnalisée (prioritaire dans le scope)
            hit = None
            for c in candidates:
                if c in sc["domains"]:
                    hit = (f"dom:{c}", c, sc["domains"][c])
                    break
            if hit is None:
                for cat, rule in sc["categories"].items():
                    cat_domains = self._lists.get_domains(cat)
                    found = next((c for c in candidates if c in cat_domains), None)
                    if found is not None:
                        hit = (f"cat:{cat}", found, rule)
                        break
            if hit is not None:
                matched_rules.append((scope, hit[0], hit[1], hit[2]))

        if not matched_rules:
            return Decision(blocked=False)

        decisions = [
            self._apply(scope, key, matched, rule, now)
            for scope, key, matched, rule in matched_rules
        ]
        for d in decisions:
            if d.blocked:
                return d

        # Autorisé : la minute courante compte pour chaque règle quota
        # correspondante (on ne consomme jamais de quota sur un blocage).
        for (scope, key, matched, rule), d in zip(matched_rules, decisions):
            if rule["mode"] == "quota" and not d.blocked:
                self._quota.note_activity(key)
        return decisions[0]

    def _apply(self, scope: str, key: str, matched: str, rule: dict, now: datetime) -> Decision:
        mode = rule["mode"]

        if mode == "blocked":
            return Decision(True, scope, matched, key, mode,
                            "domaine bloqué en permanence")

        if mode == "window":
            cur = now.hour * 60 + now.minute
            for w in rule.get("windows") or []:
                start, end = _hm_to_min(w[0]), _hm_to_min(w[1])
                if start is None or end is None:
                    continue
                if start <= end:
                    inside = start <= cur <= end
                else:  # plage qui traverse minuit (ex. 20:00-07:00)
                    inside = cur >= start or cur <= end
                if inside:
                    return Decision(False, scope, matched, key, mode,
                                    f"dans la fenêtre {w[0]}-{w[1]}")
            return Decision(True, scope, matched, key, mode,
                            "hors fenêtre horaire autorisée")

        if mode == "quota":
            quota = int(rule.get("quota_minutes") or 0)
            used = self._quota.used_minutes(key)
            if used >= quota:
                return Decision(True, scope, matched, key, mode,
                                f"quota journalier atteint ({used}/{quota} min)")
            # Autorisé : decide() appellera note_activity() si la décision
            # finale est « allow » (jamais de consommation sur un blocage).
            return Decision(False, scope, matched, key, mode,
                            f"quota restant {quota - used - 1}/{quota} min")

        return Decision(False)

    # ---------- statut pour l'UI ----------

    def quota_status(self) -> Dict[str, dict]:
        """{clé: {used, quota}} des règles quota actives — pour l'UI."""
        used = self._quota.status()
        out = {}
        with self._lock:
            for scope in SCOPES:
                sc = self._state[scope]
                if not sc["enabled"]:
                    continue
                for key, rule in list(sc["categories"].items()) + list(sc["domains"].items()):
                    if rule.get("mode") == "quota":
                        rk = f"cat:{key}" if key in sc["categories"] else f"dom:{key}"
                        out[rk] = {"used": used.get(rk, 0),
                                    "quota": rule.get("quota_minutes")}
        return out
