"""Module de gestion de réputation des processus pour Security Sheeld.

Fonctionnalités :
- Calcul d'empreinte SHA-256 de fichiers par blocs de 64 Ko
- Cache local SQLite avec rétention de 7 jours
- Interrogation de l'API MalwareBazaar (abuse.ch) sans dépendance tierce (urllib stdlib)
- Construction des hyperliens d'investigation (VirusTotal, ProcessLibrary, SpeedGuide)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import urllib.error
import urllib.parse
import urllib.request

import psutil


def compute_sha256(file_path: Optional[str]) -> Optional[str]:
    """Calcule le hash SHA-256 d'un fichier par morceaux de 64 Ko.

    Retourne None en cas d'erreur de permission, fichier introuvable ou erreur E/S.
    """
    if not file_path:
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return None


class ReputationCache:
    """Gestionnaire de cache SQLite pour la réputation des hashs."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            import cerbere_paths as _paths
            db_path = _paths.state_dir() / "reputation_cache.sqlite"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialise la table reputation si elle n'existe pas déjà."""
        import sqlite3

        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reputation (
                    hash_sha256 TEXT PRIMARY KEY,
                    filename TEXT,
                    reputation TEXT,
                    details_json TEXT,
                    checked_at TIMESTAMP
                )
            """
            )
            conn.commit()

    def get(self, hash_sha256: str) -> Optional[Dict[str, Any]]:
        """Retourne l'entrée en cache si elle date de moins de 7 jours, sinon None."""
        if not hash_sha256:
            return None

        import sqlite3

        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT hash_sha256, filename, reputation, details_json, checked_at
                    FROM reputation
                    WHERE hash_sha256 = ?
                """,
                    (hash_sha256,),
                )
                row = cursor.fetchone()
                if not row:
                    return None

                _, _, rep, details_json_str, checked_at_val = row

                if not checked_at_val:
                    return None

                try:
                    dt = datetime.fromisoformat(str(checked_at_val))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age_seconds = (datetime.now(timezone.utc) - dt).total_seconds()
                except Exception:
                    return None

                # Hit si checked_at < 7 jours (7 * 86400 = 604800s)
                if not (0 <= age_seconds < 7 * 86400):
                    return None

                # Ne pas utiliser un cache d'erreur (permet de re-tester plus tard)
                if rep == "error":
                    return None

                details: Dict[str, Any] = {}
                if details_json_str:
                    try:
                        details = json.loads(details_json_str)
                    except Exception:
                        details = {}

                return {
                    "reputation": rep,
                    "signature": details.get("signature"),
                    "file_type": details.get("file_type"),
                    "tags": details.get("tags") or [],
                    "cached": True,
                    "source": "cache",
                }
        except Exception as e:
            print(f"Erreur lecture cache SQLite reputation: {e}")
            return None

    def set(
        self,
        hash_sha256: str,
        filename: Optional[str],
        reputation: str,
        details: Dict[str, Any],
    ) -> None:
        """Enregistre ou met à jour une entrée dans le cache SQLite."""
        if not hash_sha256:
            return

        import sqlite3

        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            details_str = json.dumps(details or {}, ensure_ascii=False)
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO reputation (hash_sha256, filename, reputation, details_json, checked_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (hash_sha256, filename or "", reputation, details_str, now_iso),
                )
                conn.commit()
        except Exception as e:
            print(f"Erreur écriture cache SQLite reputation: {e}")


def query_malwarebazaar_sync(sha256: str) -> Dict[str, Any]:
    """Interroge l'API MalwareBazaar de manière synchrone (délai max 4s).

    Retourne un dictionnaire contenant réputation, signature, file_type, tags et erreur éventuelle.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("utf-8")
    headers = {
        "User-Agent": "SecuritySheeld/1.0",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if api_key:
        headers["Auth-Key"] = api_key

    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
            query_status = payload.get("query_status")

            if query_status == "ok":
                data_list = payload.get("data")
                first_data = data_list[0] if data_list and len(data_list) > 0 else {}
                return {
                    "reputation": "malicious",
                    "signature": first_data.get("signature"),
                    "file_type": first_data.get("file_type"),
                    "tags": first_data.get("tags") or [],
                }
            elif query_status in ("hash_not_found", "illegal_hash"):
                return {
                    "reputation": "clean",
                    "signature": None,
                    "file_type": None,
                    "tags": [],
                }
            else:
                return {
                    "reputation": "error",
                    "signature": None,
                    "file_type": None,
                    "tags": [],
                    "error": "timeout_or_unreachable",
                }
    except Exception:
        return {
            "reputation": "error",
            "signature": None,
            "file_type": None,
            "tags": [],
            "error": "timeout_or_unreachable",
        }


_cache_singleton: Optional[ReputationCache] = None


def get_reputation_cache() -> ReputationCache:
    """Retourne l'instance unique du cache de réputation."""
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = ReputationCache()
    return _cache_singleton


async def check_reputation(sha256: Optional[str], filename: Optional[str] = None) -> Dict[str, Any]:
    """Vérifie la réputation d'un hash via le cache SQLite ou l'API MalwareBazaar.

    Exécute la requête HTTP dans un thread séparé via asyncio.to_thread pour éviter tout blocage.
    """
    if not sha256:
        return {
            "reputation": "unknown",
            "signature": None,
            "file_type": None,
            "tags": [],
            "source": "none",
            "cached": False,
        }

    cache = get_reputation_cache()
    cached_entry = cache.get(sha256)
    if cached_entry is not None:
        return cached_entry

    # Requête réseau asynchrone non-bloquante
    res = await asyncio.to_thread(query_malwarebazaar_sync, sha256)
    res["cached"] = False
    res["source"] = "MalwareBazaar"

    # Sauvegarde en cache si réputation concluante
    if res["reputation"] in ("malicious", "clean"):
        cache.set(
            hash_sha256=sha256,
            filename=filename,
            reputation=res["reputation"],
            details={
                "signature": res.get("signature"),
                "file_type": res.get("file_type"),
                "tags": res.get("tags") or [],
            },
        )

    return res


def build_links(sha256: Optional[str], process_name: Optional[str]) -> Dict[str, Any]:
    """Construit les liens d'investigation VirusTotal, ProcessLibrary et SpeedGuide."""
    vt_hash = f"https://www.virustotal.com/gui/search/{sha256}" if sha256 else None
    vt_name = f"https://www.virustotal.com/gui/search/{process_name}" if process_name else None

    # Name sans extension, en minuscules pour ProcessLibrary
    if process_name:
        name_no_ext = os.path.splitext(process_name)[0].lower()
        proc_lib = f"https://www.processlibrary.com/en/directory/files/{name_no_ext}/" if name_no_ext else None
    else:
        proc_lib = None

    return {
        "virustotal_hash": vt_hash,
        "virustotal_name": vt_name,
        "processlibrary": proc_lib,
        "speedguide_port": None,
    }


async def inspect_process_by_pid(pid: int) -> Dict[str, Any]:
    """Inspecte un processus par son PID : chemin, SHA-256, réputation MalwareBazaar et liens.

    Lève ProcessLookupError si le PID n'existe pas.
    """
    if not psutil.pid_exists(pid):
        raise ProcessLookupError(f"Processus PID {pid} inexistant")

    try:
        proc = psutil.Process(pid)
        process_name = proc.name()
    except psutil.NoSuchProcess:
        raise ProcessLookupError(f"Processus PID {pid} inexistant")
    except psutil.AccessDenied:
        process_name = f"PID_{pid}"

    # Chemin exécutable réel
    exe_path: Optional[str] = None
    try:
        p_exe = proc.exe()
        if p_exe and p_exe.strip():
            exe_path = p_exe
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        exe_path = None

    # SHA-256 par blocs de 64 Ko
    sha256 = compute_sha256(exe_path) if exe_path else None

    # Réputation
    filename = os.path.basename(exe_path) if exe_path else process_name
    rep_info = await check_reputation(sha256, filename=filename)

    links = build_links(sha256, process_name)

    result = {
        "pid": pid,
        "process_name": process_name,
        "exe_path": exe_path,
        "sha256": sha256,
        "reputation": rep_info["reputation"],
        "signature": rep_info.get("signature"),
        "file_type": rep_info.get("file_type"),
        "tags": rep_info.get("tags") or [],
        "source": rep_info["source"],
        "cached": rep_info["cached"],
        "links": links,
    }
    if rep_info.get("error"):
        result["error"] = rep_info["error"]

    return result
