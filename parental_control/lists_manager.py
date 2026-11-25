"""Gestionnaire de listes de domaines par catégorie pour le contrôle parental/domestique.

Télécharge et met en cache les listes « The Blocklist Project » (licence
Unlicense — usage libre, aucune clé requise) et charge les listes curées
locales versionnées dans ``parental_control/curated/*.txt``.

Conventions reprises de ``tracker_filter`` :
    - téléchargement via urllib (stdlib) avec le même User-Agent ;
    - cache sous ``web_port_dashboard/state/`` (sous-dossier ``parental_lists/``) ;
    - TTL de fraîcheur contrôlé par la date de modification des fichiers ;
    - écritures atomiques (fichier .tmp + os.replace) ;
    - fail-open : en cas d'erreur réseau, le cache existant (même périmé) est servi ;
    - jamais de contenu de liste dans les logs (uniquement des compteurs).
"""

import logging
import os
import re
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

logger = logging.getLogger("parental_control.lists_manager")

# Listes distantes « The Blocklist Project » (Unlicense — usage libre).
BLOCKLIST_BASE_URL = "https://blocklistproject.github.io/Lists"
REMOTE_LISTS: Dict[str, str] = {
    "adult": f"{BLOCKLIST_BASE_URL}/porn.txt",
    "gambling": f"{BLOCKLIST_BASE_URL}/gambling.txt",
    "drugs": f"{BLOCKLIST_BASE_URL}/drugs.txt",
    "scam": f"{BLOCKLIST_BASE_URL}/scam.txt",
    "malware": f"{BLOCKLIST_BASE_URL}/malware.txt",
    "social_facebook": f"{BLOCKLIST_BASE_URL}/facebook.txt",
    "social_twitter": f"{BLOCKLIST_BASE_URL}/twitter.txt",
    "social_tiktok": f"{BLOCKLIST_BASE_URL}/tiktok.txt",
    "social_youtube": f"{BLOCKLIST_BASE_URL}/youtube.txt",
    "social_whatsapp": f"{BLOCKLIST_BASE_URL}/whatsapp.txt",
}

DEFAULT_TTL_SECONDS = 86400.0  # 24 h
_DOWNLOAD_TIMEOUT = 15  # secondes (identique au filtre de trackers existant)

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityShield/1.0"

# Jeton IPv4 en tête de ligne (format hosts : 0.0.0.0 / 127.0.0.1 ...).
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Caractères autorisés dans un nom de domaine normalisé.
_VALID_DOMAIN_CHARS_RE = re.compile(r"^[a-z0-9.-]+$")
# Nom de fichier de cache sûr.
_SAFE_NAME_RE = re.compile(r"[^a-z0-9_-]+")


def _is_ip_like(token: str) -> bool:
    """Indique si le jeton ressemble à une adresse IP (v4 ou v6) plutôt qu'à un domaine.

    NB : un jeton contenant « : » est forcément une IPv6 — les deux-points ne
    sont jamais valides dans un nom de domaine. On évite volontairement un
    test « caractères hexadécimaux » qui rejetterait des domaines légitimes
    comme ``decaf.bad`` ou ``abc.def``.
    """
    t = token.strip("[]")
    if _IPV4_RE.match(t):
        return True
    return ":" in t


def normalize_domain(token: str) -> Optional[str]:
    """Normalise un jeton brut en nom de domaine minuscule, ou retourne None si invalide.

    Règles :
        - minuscules, suppression du « . » terminal (FQDN) et des préfixes ``*.`` ;
        - seuls les caractères [a-z0-9.-] sont acceptés ;
        - chaque label doit être non vide, sans « - » initial/final, ≤ 63 car. ;
        - les jetons « IP » (0.0.0.0, ::1, ...) sont rejetés.
    """
    if not token:
        return None

    domain = token.strip().lower().lstrip("*.").rstrip(".")
    if not domain or len(domain) > 253:
        return None
    if _is_ip_like(domain):
        return None
    if not _VALID_DOMAIN_CHARS_RE.match(domain):
        return None

    for label in domain.split("."):
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None

    return domain


def parse_list_text(text: str) -> Set[str]:
    """Extrait les domaines d'une liste Blocklist Project / format hosts.

    Formats tolérés :
        - ``0.0.0.0 domaine`` (et toute IP en tête de ligne, v4/v6) ;
        - variante « -nl » : un domaine nu par ligne ;
        - lignes vides et commentaires (#, !) ignorés ;
        - commentaires en fin de ligne (# ...) ignorés ;
        - lignes contenant uniquement une IP ignorées.

    Args:
        text: Contenu texte brut de la liste.

    Returns:
        Ensemble de domaines normalisés en minuscules (matching par suffixe).
    """
    domains: Set[str] = set()

    for raw_line in text.splitlines():
        # Retirer commentaires pleine ligne et en fin de ligne.
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue

        tokens = line.split()
        if not tokens:
            continue

        # Format hosts : le 1er jeton est une IP -> le domaine est le 2e jeton.
        if _is_ip_like(tokens[0]):
            if len(tokens) < 2:
                continue  # ligne « IP seule »
            candidate = tokens[1]
        else:
            candidate = tokens[0]

        domain = normalize_domain(candidate)
        if domain:
            domains.add(domain)
            # Les listes stockent souvent uniquement la variante « www. » :
            # on ajoute le domaine nu pour que l'un et l'autre soient bloqués.
            if domain.startswith("www."):
                domains.add(domain[4:])

    return domains


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


def _atomic_write_lines(path: Path, lines: Iterable[str]) -> None:
    """Écrit des lignes dans path de façon atomique (tmp + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")
    os.replace(tmp, path)


class ListsManager:
    """Gestionnaire thread-safe des listes de domaines par catégorie.

    Attributs:
        remote_lists: Mapping catégorie -> URL des listes distantes.
        cache_dir: Répertoire de cache (``<state_dir>/parental_lists/``).
        curated_dir: Répertoire des listes curées locales.
    """

    def __init__(
        self,
        state_dir: Optional[str] = None,
        curated_dir: Optional[str] = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        remote_lists: Optional[Dict[str, str]] = None,
    ):
        """Initialise le gestionnaire et charge les listes curées.

        Args:
            state_dir: Répertoire d'état (défaut : ``web_port_dashboard/state``).
                Le cache des listes distantes est stocké dans ``state_dir/parental_lists/``.
            curated_dir: Répertoire des listes curées (défaut : ``parental_control/curated``).
            ttl_seconds: Durée de validité du cache distant en secondes (défaut : 24 h).
            remote_lists: Mapping catégorie -> URL alternatif (tests).
        """
        if state_dir is None:
            import cerbere_paths as _paths
            state_dir = _paths.state_dir()
        self._cache_dir = Path(state_dir) / "parental_lists"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        if curated_dir is None:
            try:
                import cerbere_paths as _paths
                curated_dir = _paths.bundled_file("parental_control", "curated")
            except ImportError:
                curated_dir = Path(__file__).resolve().parent / "curated"
        self._curated_dir = Path(curated_dir)

        self._ttl_seconds = float(ttl_seconds)
        self.remote_lists: Dict[str, str] = dict(remote_lists or REMOTE_LISTS)

        self._lock = threading.RLock()
        self._remote_domains: Dict[str, Set[str]] = {}
        self._remote_loaded: Set[str] = set()  # catégories dont le cache a été lu
        self._curated_domains: Dict[str, Set[str]] = {}

        self._load_curated()

    # ------------------------------------------------------------------
    # Chemins et helpers internes
    # ------------------------------------------------------------------

    def _cache_file(self, category: str) -> Path:
        """Retourne le fichier de cache associé à une catégorie distante."""
        safe = _SAFE_NAME_RE.sub("_", category.lower())
        return self._cache_dir / f"{safe}.txt"

    @staticmethod
    def _curated_category_name(path: Path) -> str:
        """Déduit le nom de catégorie d'un fichier curé (stem sans suffixe ``_domains``)."""
        stem = path.stem.lower()
        for suffix in ("_domains", "_domain"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        return stem

    def _load_cache_file(self, category: str) -> Set[str]:
        """Charge une catégorie depuis son fichier de cache (sans appel réseau)."""
        domains: Set[str] = set()
        cache_file = self._cache_file(category)
        if cache_file.is_file():
            try:
                with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                    for raw_line in f:
                        domain = normalize_domain(raw_line)
                        if domain:
                            domains.add(domain)
                            # Même expansion que parse_list_text : « www.x »
                            # couvre aussi le domaine nu.
                            if domain.startswith("www."):
                                domains.add(domain[4:])
            except Exception as e:
                logger.warning(
                    "Erreur lecture cache %s pour la catégorie '%s': %s",
                    cache_file, category, e,
                )
        with self._lock:
            self._remote_domains[category] = domains
            self._remote_loaded.add(category)
        return domains

    def _load_curated(self) -> None:
        """Charge (ou recharge) les listes curées depuis ``curated_dir``."""
        curated: Dict[str, Set[str]] = {}
        try:
            files = sorted(self._curated_dir.glob("*.txt")) if self._curated_dir.is_dir() else []
        except Exception as e:
            logger.warning("Erreur listage du dossier curé %s: %s", self._curated_dir, e)
            files = []

        for path in files:
            category = self._curated_category_name(path)
            if not category:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    domains = parse_list_text(f.read())
                curated.setdefault(category, set()).update(domains)
            except Exception as e:
                logger.warning("Erreur lecture liste curée %s: %s", path, e)

        with self._lock:
            self._curated_domains = curated
        logger.info(
            "Listes curées chargées : %d catégories depuis %s",
            len(curated), self._curated_dir,
        )

    def _cache_is_fresh(self, cache_file: Path) -> bool:
        """Indique si le fichier de cache est encore dans son TTL."""
        try:
            return (time.time() - cache_file.stat().st_mtime) <= self._ttl_seconds
        except Exception:
            return False

    def _peek_remote_domains(self, category: str) -> Set[str]:
        """Retourne les domaines distants connus sans jamais télécharger (mémoire puis cache)."""
        with self._lock:
            if category in self._remote_loaded:
                return set(self._remote_domains.get(category, set()))
        return self._load_cache_file(category)

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def refresh(
        self,
        categories: Optional[Iterable[str]] = None,
        force: bool = False,
    ) -> Dict[str, dict]:
        """Télécharge/actualise les listes distantes dans le cache (TTL 24 h, fail-open).

        Pour chaque catégorie :
            - cache frais et ``force=False`` -> statut ``"cached"`` (pas de réseau) ;
            - téléchargement réussi -> statut ``"ok"`` et écriture atomique du cache ;
            - échec réseau -> statut ``"stale"`` si un cache existant est servi,
              sinon ``"error"`` (fail-open, jamais d'exception propagée).

        Recharge également les listes curées depuis le disque.

        Args:
            categories: Catégories distantes à rafraîchir (défaut : toutes).
            force: Si True, ignore le TTL et retélécharge.

        Returns:
            Dictionnaire {catégorie: {"status", "count", "source"}}.
        """
        results: Dict[str, dict] = {}
        targets = list(categories) if categories is not None else list(self.remote_lists)

        for category in targets:
            url = self.remote_lists.get(category)
            if url is None:
                results[category] = {
                    "status": "unknown_category",
                    "count": 0,
                    "source": "remote",
                }
                continue

            cache_file = self._cache_file(category)

            if not force and cache_file.is_file() and self._cache_is_fresh(cache_file):
                domains = self._load_cache_file(category)
                results[category] = {
                    "status": "cached",
                    "count": len(domains),
                    "source": "remote",
                }
                continue

            try:
                logger.info("Téléchargement de la liste '%s' depuis %s", category, url)
                content = _download(url)
                domains = parse_list_text(content.decode("utf-8", errors="ignore"))
                if not domains:
                    raise ValueError("liste téléchargée vide ou illisible")

                _atomic_write_lines(cache_file, sorted(domains))
                with self._lock:
                    self._remote_domains[category] = domains
                    self._remote_loaded.add(category)
                logger.info(
                    "Liste '%s' mise en cache : %d domaines -> %s",
                    category, len(domains), cache_file,
                )
                results[category] = {
                    "status": "ok",
                    "count": len(domains),
                    "source": "remote",
                }
            except Exception as e:
                # FAIL-OPEN : servir le cache périmé s'il existe.
                logger.warning(
                    "Échec du téléchargement de '%s' (%s) — utilisation du cache si disponible",
                    category, e,
                )
                stale = self._load_cache_file(category)
                results[category] = {
                    "status": "stale" if stale else "error",
                    "count": len(stale),
                    "source": "remote",
                }

        # Les listes curées sont relues à chaque refresh (fichiers versionnés).
        self._load_curated()
        return results

    def get_domains(self, category: str) -> frozenset:
        """Retourne les domaines normalisés d'une catégorie (matching par suffixe).

        Ordre de résolution : mémoire -> cache disque -> téléchargement (remote
        uniquement, fail-open). Les domaines curés et distants d'une même
        catégorie sont fusionnés.

        Args:
            category: Nom de la catégorie (ex. ``"adult"``, ``"payment"``).

        Returns:
            frozenset de domaines en minuscules (vide si indisponible).
        """
        category = str(category).lower()
        domains: Set[str] = set()

        with self._lock:
            domains.update(self._curated_domains.get(category, set()))

        if category in self.remote_lists:
            with self._lock:
                loaded = category in self._remote_loaded
                if loaded:
                    domains.update(self._remote_domains.get(category, set()))
            if not loaded:
                cache_file = self._cache_file(category)
                if cache_file.is_file():
                    domains.update(self._load_cache_file(category))
                else:
                    # Aucun cache : tentative de téléchargement (fail-open).
                    self.refresh(categories=[category])
                    with self._lock:
                        domains.update(self._remote_domains.get(category, set()))

        return frozenset(domains)

    def get_all_domains(self, categories: Iterable[str]) -> frozenset:
        """Retourne l'union des domaines de plusieurs catégories (contrat moteur de règles).

        Args:
            categories: Catégories à fusionner (ex. ``["adult", "payment"]``).

        Returns:
            frozenset de domaines en minuscules.
        """
        merged: Set[str] = set()
        for category in categories:
            merged.update(self.get_domains(category))
        return frozenset(merged)

    def list_categories(self) -> Dict[str, dict]:
        """Décrit toutes les catégories connues (distantes + curées), sans réseau.

        Returns:
            {catégorie: {
                "count": nombre de domaines disponibles (curés ∪ cache distant),
                "source": "remote" | "curated" ("curated" si un fichier local existe),
                "last_updated": ISO 8601 de la dernière écriture du cache/fichier,
                "enabled": True si des domaines sont disponibles,
                "cached": True si un fichier de cache distant existe,
            }}
        """
        info: Dict[str, dict] = {}

        for category in sorted(self.remote_lists):
            domains = self._peek_remote_domains(category)
            cache_file = self._cache_file(category)
            cached = cache_file.is_file()
            info[category] = {
                "count": len(domains),
                "source": "remote",
                "last_updated": _iso_mtime(cache_file) if cached else None,
                "enabled": bool(domains),
                "cached": cached,
            }

        with self._lock:
            curated_items = dict(self._curated_domains)
        for category in sorted(curated_items):
            domains = set(curated_items[category])
            entry = info.get(category)
            if entry is not None:
                # Collision : les domaines curés s'ajoutent aux distants.
                domains |= self._peek_remote_domains(category)
                entry.update(
                    {
                        "count": len(domains),
                        "source": "curated",
                        "enabled": bool(domains),
                    }
                )
                continue
            curated_file = self._curated_dir / f"{category}.txt"
            if not curated_file.is_file():
                matches = [
                    p for p in (self._curated_dir.glob("*.txt") if self._curated_dir.is_dir() else [])
                    if self._curated_category_name(p) == category
                ]
                curated_file = matches[0] if matches else curated_file
            info[category] = {
                "count": len(domains),
                "source": "curated",
                "last_updated": _iso_mtime(curated_file),
                "enabled": bool(domains),
                "cached": False,
            }

        return info
