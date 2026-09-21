"""Résolution centralisée des chemins — compatible source et PyInstaller (frozen).

Mode source (développement, tests) :
    Tout reste dans le dépôt, chemins identiques à aujourd'hui.

Mode frozen (exe packagé) :
    - Lecture (assets embarqués : static/, curated/, data/, scripts/) -> sys._MEIPASS
    - Écriture (état, logs, config, plans) -> %LOCALAPPDATA%\\CerbereShield
"""

import os
import shutil
import sys
from pathlib import Path

APP_DIR_NAME = "CerbereShield"


def is_frozen() -> bool:
    """True si l'application tourne depuis un binaire PyInstaller."""
    return getattr(sys, "frozen", False)


def project_root() -> Path:
    """Racine des ressources en lecture seule (bundle PyInstaller ou dépôt)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    return Path(__file__).resolve().parent


def data_root() -> Path:
    """Racine inscriptible des données utilisateur (état, logs, plans, config)."""
    if is_frozen():
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) / APP_DIR_NAME if base else Path.home() / ".cerbere_shield"
    else:
        root = Path(__file__).resolve().parent
    root.mkdir(parents=True, exist_ok=True)
    return root


def module_dir() -> Path:
    """Répertoire ``web_port_dashboard`` (bundle ou source)."""
    return project_root() / "web_port_dashboard"


def state_dir() -> Path:
    """Répertoire d'état persistant (``state/``).

    Source : ``web_port_dashboard/state`` (emplacement historique).
    Frozen : ``%LOCALAPPDATA%\\CerbereShield\\state``.
    """
    d = data_root() / "state" if is_frozen() else module_dir() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir() -> Path:
    """Répertoire des journaux (``logs/``)."""
    d = data_root() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def plans_dir() -> Path:
    """Répertoire des fichiers de plan (hardening_plan.json, audit_data.json).

    En mode source, l'emplacement historique est conservé pour ne pas casser
    les scripts existants ; en frozen tout est sous ``data_root()``.
    """
    if is_frozen():
        return data_root()
    return module_dir()


def writable_root() -> Path:
    """Équivalent inscriptible de la racine projet (pour audit_data.json)."""
    return data_root() if is_frozen() else project_root()


def config_file(name: str = "config.yml", package: str = "web_port_dashboard") -> Path:
    """Chemin d'un fichier de config lisible ET inscriptible.

    En frozen, le fichier est amorcé dans ``data_root()/config/`` depuis la
    copie embarquée au premier accès, puis devient éditable par l'utilisateur.
    """
    if not is_frozen():
        return project_root() / package / name
    target = data_root() / "config" / name
    if not target.exists():
        bundled = project_root() / package / name
        if bundled.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bundled, target)
    return target


def bundled_file(*relative_parts: str) -> Path:
    """Chemin d'une ressource en lecture seule (asset embarqué ou fichier du dépôt)."""
    return project_root().joinpath(*relative_parts)
