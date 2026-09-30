"""Audit d'hygiène des cookies des navigateurs (scan + purge ciblée).

Outil passif : HTTPS rend le filtrage temps réel des cookies impossible, on se
limite donc à inspecter les bases SQLite locales et à supprimer uniquement les
cookies dont l'hôte correspond à un domaine suspect.

Navigateurs couverts (Windows) :
- Chrome  : %LOCALAPPDATA%/Google/Chrome/User Data/<profil>/Network/Cookies
- Edge    : %LOCALAPPDATA%/Microsoft/Edge/User Data/<profil>/Network/Cookies
- Firefox : %APPDATA%/Mozilla/Firefox/Profiles/<profil>/cookies.sqlite

Les bases peuvent être verrouillées quand le navigateur tourne : le scan
travaille sur une copie temporaire (fallback : ouverture SQLite en mode
immutable, puis VACUUM INTO). La purge écrit dans la base réelle et échoue
proprement si elle est verrouillée.

Sécurité : jamais de déchiffrement ni de lecture des valeurs de cookies —
seuls host_key/name sont consultés, et jamais journalisés au-delà de l'hôte.
"""

import logging
import os
import shutil
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger("cerbere.cookies_scanner")

BROWSERS = ("chrome", "edge", "firefox")

# Sévérité pour agréger le statut d'un navigateur sur plusieurs profils.
_SCAN_RANK = {"absent": 0, "ok": 1, "locked-fallback-used": 2, "inaccessible": 3}


@dataclass
class Finding:
    """Cookie repéré sur un domaine suspect (aucune valeur stockée)."""

    browser: str
    profile: str
    host_key: str
    cookie_name: str
    matched_domain: str


@dataclass
class _DbInfo:
    """Localisation d'une base de cookies et schéma associé."""

    browser: str
    profile: str
    path: Path
    table: str      # "cookies" (Chromium) | "moz_cookies" (Firefox)
    host_col: str   # "host_key" (Chromium) | "host" (Firefox)


def _normalize_domain(domain: str) -> str:
    """Normalise un domaine suspect : minuscules, sans point initial."""
    return str(domain).strip().lower().lstrip(".")


def _match_domain(host: str, suspects: Set[str]) -> Optional[str]:
    """Retourne le domaine suspect dont `host` est suffixe (par label), ou None.

    Le host_key Chromium commence souvent par '.' (cookie de domaine) ; on le
    retire avant comparaison. ".sub.ex.com" matche "ex.com" mais pas "x.com".
    """
    h = host.strip().lower().lstrip(".")
    if not h:
        return None
    for d in suspects:
        if h == d or h.endswith("." + d):
            return d
    return None


def _safe_unlink(path: Optional[str]) -> None:
    """Supprime un fichier temporaire (et ses sidecars WAL) sans exception."""
    if not path:
        return
    for p in (path, path + "-wal", path + "-shm", path + "-journal"):
        try:
            os.unlink(p)
        except OSError:
            pass


def _discover_dbs() -> List[_DbInfo]:
    """Inventorie les bases de cookies présentes sur la machine.

    Les chemins absents (navigateur non installé, variables d'environnement
    manquantes) sont simplement ignorés.
    """
    dbs: List[_DbInfo] = []
    seen: Set[Path] = set()
    local = os.environ.get("LOCALAPPDATA")
    roaming = os.environ.get("APPDATA")

    chromium_roots = []
    if local:
        chromium_roots = [
            ("chrome", Path(local) / "Google" / "Chrome" / "User Data"),
            ("edge", Path(local) / "Microsoft" / "Edge" / "User Data"),
        ]
    for browser, root in chromium_roots:
        # "Network/Cookies" = versions récentes ; "Cookies" = schéma historique.
        for pattern in ("*/Network/Cookies", "*/Cookies"):
            if not root.is_dir():
                break
            for path in sorted(root.glob(pattern)):
                if not path.is_file() or path in seen:
                    continue
                seen.add(path)
                profile = path.parent.parent.name if path.parent.name == "Network" else path.parent.name
                dbs.append(_DbInfo(browser, profile, path, "cookies", "host_key"))

    if roaming:
        prof_root = Path(roaming) / "Mozilla" / "Firefox" / "Profiles"
        if prof_root.is_dir():
            for path in sorted(prof_root.glob("*/cookies.sqlite")):
                if path.is_file() and path not in seen:
                    seen.add(path)
                    dbs.append(_DbInfo("firefox", path.parent.name, path, "moz_cookies", "host"))
    return dbs


class CookieScanner:
    """Scanner/purgeur de cookies suspect — thread-safe, stdlib uniquement.

    Attributs:
        last_status (Dict[str, str]): statut du dernier scan par navigateur
            ("ok", "locked-fallback-used", "inaccessible", "absent").
        last_status_detail (Dict[str, str]): même statut par profil,
            clé "browser/profil".
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.last_status: Dict[str, str] = {}
        self.last_status_detail: Dict[str, str] = {}

    # ------------------------------------------------------------------ scan

    def scan(self, suspect_domains: Iterable[str]) -> List[Finding]:
        """Inspecte toutes les bases trouvées et retourne les cookies suspects.

        Args:
            suspect_domains: domaines normalisés ; un cookie matche si son
                host_key est le domaine ou un sous-domaine (suffixe par label).
        """
        suspects = {_normalize_domain(d) for d in suspect_domains}
        suspects.discard("")
        findings: List[Finding] = []
        status: Dict[str, str] = {b: "absent" for b in BROWSERS}
        detail: Dict[str, str] = {}
        if not suspects:
            with self._lock:
                self.last_status, self.last_status_detail = status, detail
            return findings

        with self._lock:
            for db in _discover_dbs():
                st, found = self._scan_db(db, suspects)
                detail[f"{db.browser}/{db.profile}"] = st
                findings.extend(found)
                if _SCAN_RANK.get(st, 3) > _SCAN_RANK.get(status[db.browser], 0):
                    status[db.browser] = st
            self.last_status, self.last_status_detail = status, detail

        logger.info(
            "Scan cookies : %d domaines suspects, %d cookies repérés (statuts=%s)",
            len(suspects), len(findings), status,
        )
        return findings

    def _scan_db(self, db: _DbInfo, suspects: Set[str]) -> Tuple[str, List[Finding]]:
        """Scanne une base (via copie/fallback) ; retourne (statut, findings)."""
        conn, st, tmp = self._snapshot(db)
        if conn is None:
            return st, []
        try:
            if not self._has_table(conn, db.table):
                logger.warning("Table %s absente dans %s — base ignorée", db.table, db.path)
                return "inaccessible", []
            out: List[Finding] = []
            for host, name in conn.execute(f"SELECT {db.host_col}, name FROM {db.table}"):
                dom = _match_domain(str(host or ""), suspects)
                if dom:
                    out.append(Finding(db.browser, db.profile, str(host), str(name or ""), dom))
            return st, out
        except sqlite3.DatabaseError as e:
            logger.warning("Base cookies corrompue ignorée (%s) : %s", db.path, e)
            return "inaccessible", []
        finally:
            conn.close()
            _safe_unlink(tmp)

    @staticmethod
    def _has_table(conn: sqlite3.Connection, table: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None

    def _snapshot(
        self, db: _DbInfo
    ) -> Tuple[Optional[sqlite3.Connection], str, Optional[str]]:
        """Ouvre la base en lecture malgré un éventuel verrouillage navigateur.

        Retourne (connexion, statut, fichier_temp_à_nettoyer). Stratégie :
        1) copie vers un fichier temporaire (cas nominal) ;
        2) URI immutable — SQLite ignore totalement les verrous ;
        3) VACUUM INTO depuis une connexion read-only.
        """
        tmp: Optional[str] = None
        try:
            fd, tmp = tempfile.mkstemp(prefix="cerbere_cookies_", suffix=".db")
            os.close(fd)
            shutil.copy(str(db.path), tmp)
            # Chromium est en WAL : les cookies récents vivent dans les sidecars,
            # on les copie pour un snapshot à jour (SQLite les rejoue seul).
            for suffix in ("-wal", "-shm"):
                side = Path(str(db.path) + suffix)
                if side.is_file():
                    shutil.copy(str(side), tmp + suffix)
            conn = sqlite3.connect(tmp)
            conn.execute("PRAGMA query_only = ON")
            return conn, "ok", tmp
        except (OSError, sqlite3.Error) as e:
            logger.info("Copie impossible pour %s (%s) — fallback lecture", db.path, e)

        uri_ro = db.path.as_uri() + "?mode=ro"
        try:
            conn = sqlite3.connect(uri_ro + "&immutable=1", uri=True)
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            _safe_unlink(tmp)
            return conn, "locked-fallback-used", None
        except sqlite3.Error as e:
            logger.info("Ouverture immutable impossible pour %s (%s)", db.path, e)

        try:
            _safe_unlink(tmp)  # VACUUM INTO exige une cible inexistante
            fd, tmp = tempfile.mkstemp(prefix="cerbere_cookies_", suffix=".db")
            os.close(fd)
            _safe_unlink(tmp)
            src = sqlite3.connect(uri_ro, uri=True, timeout=1.0)
            try:
                src.execute(f"VACUUM INTO '{tmp.replace(chr(39), chr(39) * 2)}'")
            finally:
                src.close()
            conn = sqlite3.connect(tmp)
            conn.execute("PRAGMA query_only = ON")
            return conn, "locked-fallback-used", tmp
        except (OSError, sqlite3.Error) as e:
            logger.warning("Base cookies inaccessible %s : %s", db.path, e)
            _safe_unlink(tmp)
            return None, "inaccessible", None

    # ----------------------------------------------------------------- purge

    def purge(
        self, items: Iterable[Union[Finding, Tuple[str, str]]]
    ) -> Dict[str, object]:
        """Supprime uniquement les cookies signalés — jamais de purge globale.

        Args:
            items: Finding (suppression précise host+name sur son profil) ou
                tuples (browser, host_key) — supprime tous les cookies de cet
                hôte sur tous les profils du navigateur.

        Retourne un rapport {"deleted_total": int, "browsers": {browser:
        {"status": ..., "deleted": int, "profiles": {profil: {...}}}}}.
        """
        # Regroupe les cibles par (browser, profil) : Finding -> host+name
        # précis ; tuple (browser, host_key) -> tous les cookies de l'hôte.
        by_db: Dict[Tuple[str, str], Set[Tuple[str, Optional[str]]]] = {}
        with self._lock:
            dbs = {(d.browser, d.profile): d for d in _discover_dbs()}
            for it in items:
                if isinstance(it, Finding):
                    by_db.setdefault((it.browser, it.profile), set()).add(
                        (it.host_key, it.cookie_name)
                    )
                else:  # tuple (browser, host_key)
                    browser, host = str(it[0]), str(it[1])
                    for (b, prof) in dbs:
                        if b == browser:
                            by_db.setdefault((b, prof), set()).add((host, None))
        return self._purge_all(by_db, dbs)

    def _purge_all(
        self,
        by_db: Dict[Tuple[str, str], Set[Tuple[str, Optional[str]]]],
        dbs: Dict[Tuple[str, str], _DbInfo],
    ) -> Dict[str, object]:
        """Exécute les DELETE base par base et agrège le rapport."""
        browsers: Dict[str, dict] = {}
        deleted_total = 0
        for (browser, profile), targets in sorted(by_db.items()):
            db = dbs.get((browser, profile))
            p_status, deleted = self._purge_db(db, targets) if db else ("inaccessible", 0)
            entry = browsers.setdefault(
                browser, {"status": "ok", "deleted": 0, "profiles": {}}
            )
            entry["profiles"][profile] = {"status": p_status, "deleted": deleted}
            entry["deleted"] += deleted
            deleted_total += deleted
        for browser, entry in browsers.items():
            sts = {p["status"] for p in entry["profiles"].values()}
            entry["status"] = sts.pop() if len(sts) == 1 else "partial"

        report = {"deleted_total": deleted_total, "browsers": browsers}
        logger.info(
            "Purge cookies : %d supprimés (statuts=%s)",
            deleted_total,
            {b: e["status"] for b, e in browsers.items()},
        )
        return report

    @staticmethod
    def _purge_db(
        db: _DbInfo, targets: Set[Tuple[str, Optional[str]]]
    ) -> Tuple[str, int]:
        """DELETE ciblé sur la base réelle — échoue proprement si verrouillée."""
        try:
            conn = sqlite3.connect(str(db.path), timeout=3.0)
        except sqlite3.Error as e:
            logger.warning("Purge impossible, base injoignable %s : %s", db.path, e)
            return "inaccessible", 0
        try:
            before = conn.total_changes
            for host, name in targets:
                if name is None:
                    conn.execute(f"DELETE FROM {db.table} WHERE {db.host_col} = ?", (host,))
                else:
                    conn.execute(
                        f"DELETE FROM {db.table} WHERE {db.host_col} = ? AND name = ?",
                        (host, name),
                    )
            conn.commit()
            deleted = conn.total_changes - before
            # Jamais de valeur de cookie dans les logs — hôte + compteur seuls.
            logger.info(
                "Purge %s/%s : %d cookies supprimés (%d hôtes ciblés)",
                db.browser, db.profile, deleted, len(targets),
            )
            return "ok", deleted
        except sqlite3.OperationalError as e:
            conn.rollback()
            logger.warning("Purge impossible, base verrouillée %s : %s", db.path, e)
            return "locked", 0
        except sqlite3.DatabaseError as e:
            conn.rollback()
            logger.warning("Purge impossible, base corrompue %s : %s", db.path, e)
            return "inaccessible", 0
        finally:
            conn.close()
