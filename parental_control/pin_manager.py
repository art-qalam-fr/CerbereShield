"""Gestionnaire de PIN parental — distinct du mot de passe d'accès applicatif.

Le PIN (4 à 8 chiffres) protège les réglages/actions du contrôle parental.
Hash PBKDF2-HMAC-SHA256 (100 000 itérations, sel aléatoire) : même schéma que
le mot de passe d'accès du dashboard (_hash_app_password). Jamais stocké ni
logué en clair.

Usage :
    from parental_control.pin_manager import PinManager

    pins = PinManager()          # état : web_port_dashboard/state/parental_pin.json
    if not pins.is_set():
        pins.set_pin("1234")     # lève ValueError (déjà défini ou format invalide)
    if pins.verify("1234"):      # False tant que le verrouillage anti brute-force dure
        ...
    pins.change_pin("1234", "5678")
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("cerbere.parental")

# Politique PIN : 4 à 8 chiffres uniquement.
_PIN_RE = re.compile(r"^\d{4,8}$")

# Même schéma que _hash_app_password() de web_port_dashboard/port_dashboard.py.
_PBKDF2_ITERATIONS = 100_000

# Anti brute-force : après 5 échecs, backoff croissant (30 s, doublé à chaque
# palier de 5 échecs, plafonné à 600 s) — calqué sur l'endpoint /api/unlock.
_FAILURE_THRESHOLD = 5
_LOCK_BASE_SECONDS = 30
_LOCK_MAX_SECONDS = 600

# Verrou partagé par toutes les instances : plusieurs instances peuvent
# coexister et écrivent dans le même fichier d'état (cf. history_manager_simple).
_LOCK = threading.Lock()


def _hash_pin(pin: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", pin.encode("utf-8"), bytes.fromhex(salt_hex), _PBKDF2_ITERATIONS
    ).hex()


class PinManager:
    """Gère le PIN parental : création, vérification, changement, verrouillage.

    Persisté dans ``web_port_dashboard/state/parental_pin.json`` : sel + hash
    (jamais le PIN en clair) ainsi que le compteur d'échecs et la fin de
    verrouillage — le verrou anti brute-force survit donc au redémarrage.
    Écritures atomiques (tmp + os.replace), accès sérialisés par _LOCK.
    """

    def __init__(self, state_file: Path | None = None) -> None:
        if state_file is None:
            import cerbere_paths as _paths
            state_file = _paths.state_dir() / "parental_pin.json"
        self.state_file = state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load()

    def _load(self) -> Dict[str, Any]:
        """Recharge l'état depuis le disque (une autre instance a pu écrire)."""
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, ValueError) as e:
            # Fichier corrompu ≠ PIN absent : on logue pour le diagnostic.
            logger.warning("Fichier PIN parental corrompu %s : %s", self.state_file.name, e)
        return {}

    def _save(self) -> None:
        """Écriture JSON atomique : tmp + os.replace (jamais de fichier tronqué)."""
        tmp = Path(str(self.state_file) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.state_file)

    @staticmethod
    def _valid_format(pin: str) -> bool:
        return bool(_PIN_RE.fullmatch(pin or ""))

    def _is_locked(self) -> bool:
        """Prérequis : _LOCK détenu."""
        return time.time() < float(self._state.get("locked_until", 0.0))

    def _check(self, pin: str) -> bool:
        """Compare le hash ; gère compteur d'échecs et backoff. _LOCK détenu."""
        salt = self._state.get("pin_salt")
        expected = self._state.get("pin_hash")
        if (
            salt
            and expected
            and self._valid_format(pin)
            and secrets.compare_digest(_hash_pin(pin, salt), expected)
        ):
            self._state["failed_count"] = 0
            self._state["locked_until"] = 0.0
            return True
        count = int(self._state.get("failed_count", 0)) + 1
        self._state["failed_count"] = count
        if count >= _FAILURE_THRESHOLD:
            # Backoff croissant : 30 s, puis double à chaque palier de 5 échecs
            delay = min(
                _LOCK_BASE_SECONDS * (1 << (count // _FAILURE_THRESHOLD - 1)),
                _LOCK_MAX_SECONDS,
            )
            self._state["locked_until"] = time.time() + delay
            logger.warning("PIN parental verrouillé %ss après %d échecs", delay, count)
        else:
            logger.warning("Tentative de PIN parental refusée (%d échecs)", count)
        return False

    def _store_pin(self, pin: str) -> None:
        """Stocke sel + hash, réinitialise l'anti brute-force, persiste. _LOCK détenu."""
        salt = secrets.token_hex(16)
        self._state["pin_salt"] = salt
        self._state["pin_hash"] = _hash_pin(pin, salt)
        self._state["failed_count"] = 0
        self._state["locked_until"] = 0.0
        self._save()

    def is_set(self) -> bool:
        """True si un PIN parental est configuré."""
        with _LOCK:
            self._state = self._load()
            return bool(self._state.get("pin_hash") and self._state.get("pin_salt"))

    def set_pin(self, pin: str) -> None:
        """Définit le PIN initial. Lève ValueError si invalide ou déjà défini.

        Pour modifier un PIN existant, utiliser change_pin().
        """
        if not self._valid_format(pin):
            raise ValueError("PIN invalide : 4 à 8 chiffres requis.")
        with _LOCK:
            self._state = self._load()
            if self._state.get("pin_hash"):
                raise ValueError("PIN déjà défini : utiliser change_pin().")
            self._store_pin(pin)
        logger.info("PIN parental initialisé")

    def change_pin(self, old_pin: str, new_pin: str) -> bool:
        """Change le PIN après vérification de l'ancien.

        False si verrouillage actif, ancien PIN erroné (compté comme un échec)
        ou nouveau PIN au format invalide.
        """
        if not self._valid_format(new_pin):
            return False
        with _LOCK:
            self._state = self._load()
            if self._is_locked():
                return False
            if not self._check(old_pin):
                self._save()
                return False
            self._store_pin(new_pin)
        logger.info("PIN parental modifié")
        return True

    def verify(self, pin: str) -> bool:
        """Vérifie le PIN. False si non défini, erroné ou verrouillage actif."""
        with _LOCK:
            self._state = self._load()
            if self._is_locked():
                return False
            ok = self._check(pin)
            self._save()
            return ok

    def remaining_lockout_seconds(self) -> int:
        """Secondes restantes de verrouillage anti brute-force (0 si libre)."""
        with _LOCK:
            self._state = self._load()
            remaining = float(self._state.get("locked_until", 0.0)) - time.time()
            return int(remaining) + 1 if remaining > 0 else 0
