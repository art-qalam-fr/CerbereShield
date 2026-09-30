"""Gestionnaire de listes de blocage publicitaire multi-sources (PRD T60).

Registre de listes adblock (EasyList, EasyPrivacy, AdGuard DNS, OISD, Hagezi)
téléchargées à l'exécution — jamais redistribuées — et mises en cache sous
``state_dir/filter_lists/<list_id>.txt``. Les listes cochées sont persistées
dans ``state_dir/adblock_config.json`` (``{"enabled": [ids]}``).

Conventions reprises de ``parental_control/lists_manager.py`` :
    - téléchargement urllib (stdlib) avec le même User-Agent ;
    - écriture atomique du cache (fichier .tmp + os.replace) ;
    - fail-open : en cas d'erreur réseau, le cache existant (même périmé)
      est servi ;
    - expansion « www. » : une entrée ``www.x`` couvre aussi ``x`` ;
    - jamais de contenu de liste dans les logs (compteurs/statuts uniquement).

Formats de listes :
    - ``abp``     : règles ABP — seules ``||domaine^`` et ``|domaine|`` sont
      extraites (exceptions ``@@``, cosmétiques ``##``/``#?#``/``#@#``, regex
      ``/.../`` et chemins ignorés) ; tolérance aux lignes « hosts »
      (``0.0.0.0 domaine``) et domaines nus.
    - ``domains`` : un domaine nu par ligne (Hagezi ``domains/*.txt``) ;
      lignes ``#``/``!`` ignorées — délégué à ``parse_list_text``.
"""

import json
import logging
import os
import re
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set

from parental_control.lists_manager import (
    _is_ip_like,
    normalize_domain,
    parse_list_text,
)

logger = logging.getLogger("tracker_filter.list_manager")

# ---------------------------------------------------------------------------
# Registre des listes adblock (toutes gratuites, sans clé API — cf. PRD §2)
# ---------------------------------------------------------------------------

LIST_REGISTRY: Dict[str, dict] = {
    "easylist": {
        "name": "EasyList",
        "url": "https://easylist.to/easylist/easylist.txt",
        "license": "GPLv3 / CC BY-SA 3.0",
        "license_url": "https://easylist.to/pages/licence.html",
        "description": "Publicité — liste principale d'Adblock Plus / uBlock Origin.",
        "enabled_default": True,
        "format": "abp",
    },
    "easyprivacy": {
        "name": "EasyPrivacy",
        "url": "https://easylist.to/easylist/easyprivacy.txt",
        "license": "GPLv3 / CC BY-SA 3.0",
        "license_url": "https://easylist.to/pages/licence.html",
        "description": "Trackers et télémétrie — compagnon d'EasyList.",
        "enabled_default": True,
        "format": "abp",
    },
    "adguard_dns": {
        "name": "AdGuard DNS filter",
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "license": "GPLv3",
        "license_url": "https://github.com/AdguardTeam/AdGuardSDNSFilter",
        "description": "Pub + trackers optimisé pour le blocage DNS.",
        "enabled_default": False,
        "format": "abp",
    },
    "oisd_big": {
        "name": "OISD big",
        "url": "https://raw.githubusercontent.com/sjhgvr/oisd/main/oisd_big.txt",
        "license": "GPLv3",
        "license_url": "https://oisd.nl/",
        "description": "~250k domaines, pub/traqueurs, anti faux-positifs.",
        "enabled_default": False,
        "format": "abp",
    },
    "hagezi_multi": {
        "name": "HaGeZi Multi Normal",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
        "license": "GPLv3",
        "license_url": "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
        "description": "Pub / trackers / malwares — version « normal » recommandée.",
        "enabled_default": False,
        "format": "abp",
    },
}

DEFAULT_TTL_SECONDS = 7 * 86400.0  # 7 jours (EasyList annonce « Expires: 4 days »)
_DOWNLOAD_TIMEOUT = 30  # secondes
CONFIG_FILENAME = "adblock_config.json"

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityShield/1.0"

# Nom de fichier de cache sûr.
_SAFE_NAME_RE = re.compile(r"[^a-z0-9_-]+")

# Règles ABP extraites : ||domaine^ (hôte entier) et |domaine| (exact).
_ABP_HOST_RULE_RE = re.compile(
    r"^\|\|([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})\^"
)
_ABP_EXACT_RULE_RE = re.compile(
    r"^\|([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})\|$"
)
# Préfixes de lignes ABP à ignorer (commentaires, exceptions, cosmétiques).
_ABP_SKIP_PREFIXES = ("!", "[", "@@", "##", "#?#", "#@#")
# Caractères « syntaxe ABP » : leur présence disqualifie la ligne pour le
# fallback « domaine nu / hosts » (évite d'absorber des règles de chemin).
_ABP_SPECIAL_CHARS = set("|^$@#*/%,;()")


# ---------------------------------------------------------------------------
# Helpers de bas niveau (module-level pour permettre le monkeypatch en test)
# ---------------------------------------------------------------------------


def _download(url: str, timeout: int = _DOWNLOAD_TIMEOUT) -> bytes:
    """Télécharge une URL et retourne son contenu brut (lève une exception en cas d'échec)."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def _iso_mtime(path: Path) -> Optional[str]:
    """Retourne la date de modification d'un fichier en ISO 8601, ou None."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    except Exception:
        return None


def _atomic_write_text(path: Path, text: str) -> None:
    """Écrit un texte dans path de façon atomique (tmp + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _expand_www(domains: Set[str]) -> Set[str]:
    """Ajoute le domaine nu pour chaque entrée « www.x » (comme parse_list_text)."""
    expanded = set(domains)
    for d in domains:
        if d.startswith("www."):
            expanded.add(d[4:])
    return expanded


def parse_abp_domains(text: str) -> Set[str]:
    """Extrait les domaines bloqués d'une liste au format ABP / EasyList.

    Seules les règles ciblant un hôte entier sont conservées :
        - ``||domaine^`` (et variantes ``||domaine^$options``) ;
        - ``|domaine|`` (correspondance exacte).
    Les exceptions ``@@``, règles cosmétiques (``##``, ``#?#``, ``#@#``),
    expressions régulières ``/.../`` et règles de chemin sont ignorées.
    Tolérance : les lignes « hosts » (``0.0.0.0 domaine``) et les domaines
    nus présents dans certaines listes DNS (AdGuard/OISD) sont aussi pris
    en compte.

    Args:
        text: Contenu texte brut de la liste.

    Returns:
        Ensemble de domaines normalisés en minuscules (avec expansion www.).
    """
    domains: Set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(_ABP_SKIP_PREFIXES):
            continue

        # Expressions régulières pures /.../
        if line.startswith("/") and line.endswith("/") and len(line) > 1:
            continue

        m = _ABP_HOST_RULE_RE.match(line) or _ABP_EXACT_RULE_RE.match(line)
        if m:
            domain = normalize_domain(m.group(1))
            if domain:
                domains.add(domain)
            continue

        # Fallback tolérant : ligne « hosts » ou domaine nu, uniquement si la
        # ligne ne contient aucune syntaxe ABP (sinon c'est une règle de
        # chemin/regex qu'on ne sait pas interpréter -> ignorée).
        if any(c in _ABP_SPECIAL_CHARS for c in line):
            continue
        tokens = line.split()
        if len(tokens) > 2:
            continue
        if _is_ip_like(tokens[0]):
            if len(tokens) < 2:
                continue  # ligne « IP seule »
            candidate = tokens[1]
        else:
            candidate = tokens[0]
        domain = normalize_domain(candidate)
        if domain:
            domains.add(domain)

    return _expand_www(domains)


def parse_domains_format(text: str, fmt: str) -> Set[str]:
    """Parse une liste selon son format registre (« abp » ou « domains »).

    Args:
        text: Contenu texte brut de la liste.
        fmt: ``"abp"`` -> :func:`parse_abp_domains` ; ``"domains"`` ->
            :func:`parental_control.lists_manager.parse_list_text`
            (domaine nu par ligne, ``#``/``!`` ignorés, expansion www. incluse).

    Returns:
        Ensemble de domaines normalisés.
    """
    if fmt == "domains":
        return parse_list_text(text)
    return parse_abp_domains(text)


# ---------------------------------------------------------------------------
# Gestionnaire
# ---------------------------------------------------------------------------


class AdblockListManager:
    """Gestionnaire thread-safe des listes adblock (registre + cache + config).

    Attributs:
        registry: Mapping list_id -> métadonnées (copie de LIST_REGISTRY).
        cache_dir: Répertoire de cache (``<state_dir>/filter_lists/``).
    """

    def __init__(
        self,
        state_dir: Optional[str] = None,
        config_path: Optional[str] = None,
        registry: Optional[Dict[str, dict]] = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ):
        """Initialise le gestionnaire et charge la configuration persistée.

        Args:
            state_dir: Répertoire d'état (défaut : ``web_port_dashboard/state``).
                Les caches vont dans ``state_dir/filter_lists/<list_id>.txt`` et
                la config dans ``state_dir/adblock_config.json``.
            config_path: Chemin alternatif du fichier de config (tests).
            registry: Registre alternatif (tests).
            ttl_seconds: Âge au-delà duquel un cache est « stale » (défaut 7 j).
        """
        if state_dir is None:
            import cerbere_paths as _paths
            state_dir = _paths.state_dir()
        self._state_dir = Path(state_dir)
        self._cache_dir = self._state_dir / "filter_lists"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._config_path = (
            Path(config_path) if config_path else self._state_dir / CONFIG_FILENAME
        )

        self.registry: Dict[str, dict] = dict(registry or LIST_REGISTRY)
        self._ttl_seconds = float(ttl_seconds)

        self._lock = threading.RLock()
        self._enabled: Set[str] = self._load_config()
        # Mémoïsation des caches parsés : list_id -> (mtime, domaines).
        self._parsed_cache: Dict[str, tuple] = {}

    # ------------------------------------------------------------------
    # Config persistée (listes activées)
    # ------------------------------------------------------------------

    def _default_enabled(self) -> Set[str]:
        """Retourne les listes activées par défaut selon le registre."""
        return {
            lid for lid, meta in self.registry.items() if meta.get("enabled_default")
        }

    def _load_config(self) -> Set[str]:
        """Charge ``adblock_config.json`` ; défaut = enabled_default du registre."""
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            enabled_raw = data.get("enabled")
            if enabled_raw is None:
                return self._default_enabled()
            return {str(x) for x in enabled_raw if str(x) in self.registry}
        except FileNotFoundError:
            return self._default_enabled()
        except Exception as e:
            logger.warning(
                "Config adblock illisible (%s) — défauts du registre appliqués", e
            )
            return self._default_enabled()

    def _save_config_locked(self) -> None:
        """Persiste l'ensemble des listes activées (appelé sous _lock)."""
        payload = {"enabled": sorted(self._enabled)}
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._config_path.with_name(self._config_path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, self._config_path)

    def enabled_lists(self) -> list:
        """Retourne les list_ids actuellement activés (triés)."""
        with self._lock:
            return sorted(self._enabled)

    # ------------------------------------------------------------------
    # Cache disque
    # ------------------------------------------------------------------

    def _cache_file(self, list_id: str) -> Path:
        """Retourne le fichier de cache associé à une liste."""
        safe = _SAFE_NAME_RE.sub("_", str(list_id).lower())
        return self._cache_dir / f"{safe}.txt"

    def _load_list_domains(self, list_id: str) -> Set[str]:
        """Parse le cache disque d'une liste (mémoïsé par mtime, sans réseau)."""
        cache_file = self._cache_file(list_id)
        try:
            mtime = cache_file.stat().st_mtime
        except OSError:
            with self._lock:
                self._parsed_cache.pop(list_id, None)
            return set()

        with self._lock:
            memo = self._parsed_cache.get(list_id)
            if memo and memo[0] == mtime:
                return set(memo[1])

        domains: Set[str] = set()
        try:
            with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            fmt = self.registry.get(list_id, {}).get("format", "abp")
            domains = parse_domains_format(text, fmt)
        except Exception as e:
            logger.warning("Erreur lecture/parsing cache %s: %s", cache_file, e)

        with self._lock:
            self._parsed_cache[list_id] = (mtime, domains)
        return set(domains)

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def refresh(self, list_id: Optional[str] = None) -> Dict[str, dict]:
        """Télécharge les listes et écrit le cache atomiquement (fail-open).

        Args:
            list_id: Liste à rafraîchir ; None = toutes les listes ACTIVÉES.

        Returns:
            {list_id: {"status": "ok"|"error"|"cached",
                       "domains": int,
                       "updated_at": iso|None}}
            ``"cached"`` = téléchargement échoué mais cache existant servi
            (fail-open) ; ``"error"`` = échec sans cache exploitable.
        """
        if list_id is not None:
            targets = [list_id]
        else:
            with self._lock:
                targets = sorted(self._enabled)

        results: Dict[str, dict] = {}
        for lid in targets:
            meta = self.registry.get(lid)
            cache_file = self._cache_file(lid)
            if meta is None:
                results[lid] = {
                    "status": "error",
                    "domains": 0,
                    "updated_at": _iso_mtime(cache_file),
                    "error": "unknown_list",
                }
                continue

            try:
                logger.info(
                    "Téléchargement de la liste adblock '%s' depuis %s",
                    lid, meta["url"],
                )
                content = _download(meta["url"], timeout=_DOWNLOAD_TIMEOUT)
                text = content.decode("utf-8", errors="ignore")
                if not text.strip():
                    raise ValueError("liste téléchargée vide")

                with self._lock:
                    _atomic_write_text(cache_file, text)
                    self._parsed_cache.pop(lid, None)  # invalider la mémoïsation

                domains = self._load_list_domains(lid)
                logger.info(
                    "Liste adblock '%s' mise en cache : %d domaines -> %s",
                    lid, len(domains), cache_file,
                )
                results[lid] = {
                    "status": "ok",
                    "domains": len(domains),
                    "updated_at": _iso_mtime(cache_file),
                }
            except Exception as e:
                # FAIL-OPEN : servir le cache existant (même périmé).
                logger.warning(
                    "Échec du téléchargement de la liste adblock '%s' (%s) — "
                    "utilisation du cache si disponible",
                    lid, e,
                )
                cached = self._load_list_domains(lid)
                results[lid] = {
                    "status": "cached" if cached else "error",
                    "domains": len(cached),
                    "updated_at": _iso_mtime(cache_file),
                    "error": str(e),
                }

        return results

    def get_domains(self) -> Set[str]:
        """Retourne l'union des domaines des listes ACTIVÉES (depuis le cache disque).

        Returns:
            Ensemble de domaines normalisés en minuscules (matching par suffixe,
            expansion www. déjà appliquée). Vide si aucun cache disponible.
        """
        with self._lock:
            enabled = list(self._enabled)
        merged: Set[str] = set()
        for lid in enabled:
            if lid in self.registry:
                merged.update(self._load_list_domains(lid))
        return merged

    def get_sources_for(self, domain: str) -> list:
        """Retourne les list_ids ACTIVÉES contenant le domaine.

        Match exact + suffixe parent avec boundary label :
        ``a.b.x.com`` matche une entrée ``x.com`` ou ``b.x.com``,
        jamais un TLD seul.

        Args:
            domain: Domaine interrogé (casse et « . » terminal tolérés).

        Returns:
            Liste triée des list_ids sources (vide si aucune).
        """
        norm = normalize_domain(domain) or (domain or "").strip().lower().rstrip(".")
        if not norm:
            return []

        # Candidats par remontée de labels : "a.b.x.com", "b.x.com", "x.com"
        # (le dernier label seul — TLD — n'est jamais testé).
        labels = norm.split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]

        with self._lock:
            enabled = list(self._enabled)

        sources = []
        for lid in enabled:
            if lid not in self.registry:
                continue
            domains = self._load_list_domains(lid)
            if any(c in domains for c in candidates):
                sources.append(lid)
        return sorted(sources)

    def set_enabled(self, list_id: str, enabled: bool) -> dict:
        """Active/désactive une liste et persiste ``adblock_config.json``.

        Args:
            list_id: Identifiant du registre (ValueError si inconnu).
            enabled: True pour activer, False pour désactiver.

        Returns:
            :meth:`status` après modification.
        """
        if list_id not in self.registry:
            raise ValueError(f"liste adblock inconnue : {list_id}")
        with self._lock:
            if enabled:
                self._enabled.add(list_id)
            else:
                self._enabled.discard(list_id)
            self._save_config_locked()
        logger.info(
            "Liste adblock '%s' %s (activées : %d)",
            list_id, "activée" if enabled else "désactivée", len(self._enabled),
        )
        return self.status()

    def status(self) -> Dict[str, dict]:
        """Décrit chaque liste du registre (état cache + activation), sans réseau.

        Returns:
            {list_id: {
                "id", "name", "license", "license_url", "description", "url",
                "enabled": bool,
                "domains_loaded": int,
                "cache_age_hours": float|None,
                "last_update": iso|None,
                "file_size_kb": float|None,
                "status": "ok"|"stale"|"missing"|"error",
            }}
            ``"ok"`` = cache présent, parsé et dans le TTL ; ``"stale"`` =
            cache plus vieux que le TTL ; ``"missing"`` = pas de cache ;
            ``"error"`` = cache illisible ou parsé à zéro domaine.
        """
        now = time.time()
        with self._lock:
            enabled = set(self._enabled)

        info: Dict[str, dict] = {}
        for lid in sorted(self.registry):
            meta = self.registry[lid]
            cache_file = self._cache_file(lid)
            age_hours = None
            last_update = None
            size_kb = None
            domains: Set[str] = set()
            state = "missing"

            if cache_file.is_file():
                try:
                    st = cache_file.stat()
                    age_seconds = max(0.0, now - st.st_mtime)
                    age_hours = round(age_seconds / 3600.0, 2)
                    last_update = datetime.fromtimestamp(st.st_mtime).isoformat(
                        timespec="seconds"
                    )
                    size_kb = round(st.st_size / 1024.0, 1)
                    domains = self._load_list_domains(lid)
                    if not domains:
                        state = "error"
                    elif age_seconds > self._ttl_seconds:
                        state = "stale"
                    else:
                        state = "ok"
                except Exception as e:
                    logger.warning("Erreur inspection cache %s: %s", cache_file, e)
                    state = "error"

            info[lid] = {
                "id": lid,
                "name": meta["name"],
                "license": meta["license"],
                "license_url": meta["license_url"],
                "description": meta["description"],
                "url": meta["url"],
                "enabled": lid in enabled,
                "domains_loaded": len(domains),
                "cache_age_hours": age_hours,
                "last_update": last_update,
                "file_size_kb": size_kb,
                "status": state,
            }

        return info
