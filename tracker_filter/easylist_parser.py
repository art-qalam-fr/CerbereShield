"""Analyseur de règles EasyList / EasyPrivacy pour extraction de domaines bloqués.

Télécharge et extrait les domaines ciblés par les listes de blocage ABP
pour alimenter le sinkhole DNS local.
"""

import json
import logging
import os
import re
import time
import urllib.request
from typing import Dict, List, Set, Tuple

logger = logging.getLogger("tracker_filter.easylist_parser")

EASYLIST_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
]

ALLOWLIST_URLS = [
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
]



def download_lists(state_dir: str) -> List[str]:
    """Télécharge les listes EasyList et EasyPrivacy dans state_dir/filter_lists/.

    Args:
        state_dir: Répertoire de données d'état.

    Returns:
        Liste des chemins de fichiers téléchargés avec succès.
    """
    filter_dir = os.path.join(state_dir, "filter_lists")
    os.makedirs(filter_dir, exist_ok=True)
    downloaded_files = []

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityShield/1.0"}

    for url in EASYLIST_URLS:
        filename = url.split("/")[-1]
        dest_path = os.path.join(filter_dir, filename)
        logger.info("Téléchargement de %s vers %s", url, dest_path)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read()
            with open(dest_path, "wb") as f:
                f.write(content)
            downloaded_files.append(dest_path)
        except Exception as e:
            logger.warning("Échec du téléchargement de %s: %s", url, e)

    return downloaded_files


def parse_domains_meta(text: str, source_name: str) -> Dict[str, dict]:
    """Parse un texte au format EasyList / ABP et extrait les domaines avec métadonnées.

    Règles ignorées :
        - Commentaires et en-têtes (!, [)
        - Règles d'exception (@@)
        - Règles de masquage d'éléments (##, #?#)
        - Expressions régulières (/.../)

    Extraction :
        - Règles ciblant un domaine ENTIER : ||domaine^
        - Règle originale tronquée à 120 caractères
        - Normalisation en minuscules

    Args:
        text: Contenu texte de la liste de filtres.
        source_name: Nom de la source ('easylist', 'easyprivacy', etc.).

    Returns:
        Dictionnaire {domaine: {'sources': [source_name], 'rule': regle_brute_tronquee_120}}.
    """
    results: Dict[str, dict] = {}
    domain_rule = re.compile(r"^\|\|([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})\^")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Ignorer commentaires, métadonnées, exceptions et sélecteurs cosmétiques
        if line.startswith(("!", "[", "@@", "##", "#?#")):
            continue

        # Ignorer expressions régulières pures /.../
        if line.startswith("/") and line.endswith("/") and len(line) > 1:
            continue

        # Extraction des règles ciblant un domaine ENTIER : ||domaine^
        m = domain_rule.match(line)
        if m:
            domain = m.group(1).lower()
            rule_trunc = line[:120]
            if domain in results:
                if source_name and source_name not in results[domain]["sources"]:
                    results[domain]["sources"].append(source_name)
            else:
                results[domain] = {
                    "sources": [source_name] if source_name else [],
                    "rule": rule_trunc,
                }

    return results


def parse_domains(text: str) -> Set[str]:
    """Parse un texte au format EasyList / ABP et extrait l'ensemble des domaines bloqués.

    Args:
        text: Contenu texte de la liste de filtres.

    Returns:
        Set des noms de domaines extraits.
    """
    meta = parse_domains_meta(text, "")
    return set(meta.keys())


def load_domain_map(state_dir: str, max_age_days: int = 7) -> Tuple[Set[str], Dict[str, dict]]:
    """Charge l'ensemble des domaines et leurs métadonnées depuis le cache ou effectue une mise à jour.

    Parse chaque liste avec son nom ('easylist'/'easyprivacy'), fusionne les métadonnées
    avec sources cumulées, persiste domains_meta.json à côté de domains.txt,
    et recharge les deux depuis le cache si les fichiers sont frais.

    Args:
        state_dir: Répertoire racine de stockage d'état.
        max_age_days: Durée de validité maximale du cache en jours (défaut: 7).

    Returns:
        Tuple (set des domaines bloqués, dictionnaire des métadonnées).
    """
    filter_dir = os.path.join(state_dir, "filter_lists")
    domains_file = os.path.join(filter_dir, "domains.txt")
    meta_file = os.path.join(filter_dir, "domains_meta.json")

    should_refresh = True
    if os.path.isfile(domains_file) and os.path.isfile(meta_file):
        try:
            mtime = min(os.path.getmtime(domains_file), os.path.getmtime(meta_file))
            age_days = (time.time() - mtime) / 86400.0
            if age_days <= max_age_days:
                should_refresh = False
        except Exception as e:
            logger.warning("Erreur vérification date cache: %s", e)

    if not should_refresh:
        logger.info("Chargement des domaines et métadonnées depuis le cache existant: %s", domains_file)
        try:
            with open(meta_file, "r", encoding="utf-8", errors="ignore") as f:
                domain_map = json.load(f)

            domains: Set[str] = set()
            with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        domains.add(dom)

            if not domains and domain_map:
                domains = set(domain_map.keys())

            return domains, domain_map
        except Exception as e:
            logger.warning("Erreur lecture cache %s, actualisation requise: %s", meta_file, e)

    # Actualisation ou génération initiale
    logger.info("Mise à jour requise pour les listes EasyList / EasyPrivacy.")
    try:
        downloaded = download_lists(state_dir)
        # Si aucun fichier téléchargé (ex: hors-ligne), vérifier si les fichiers locaux existent
        if not downloaded:
            for url in EASYLIST_URLS:
                candidate = os.path.join(filter_dir, url.split("/")[-1])
                if os.path.isfile(candidate):
                    downloaded.append(candidate)

        combined_meta: Dict[str, dict] = {}

        for fpath in downloaded:
            if os.path.isfile(fpath):
                try:
                    fname = os.path.basename(fpath).lower()
                    if "easyprivacy" in fname:
                        source_name = "easyprivacy"
                    elif "easylist" in fname:
                        source_name = "easylist"
                    else:
                        source_name = os.path.splitext(fname)[0]

                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        file_meta = parse_domains_meta(f.read(), source_name)

                    for dom, meta in file_meta.items():
                        if dom in combined_meta:
                            for s in meta["sources"]:
                                if s not in combined_meta[dom]["sources"]:
                                    combined_meta[dom]["sources"].append(s)
                        else:
                            combined_meta[dom] = {
                                "sources": list(meta["sources"]),
                                "rule": meta["rule"],
                            }
                except Exception as read_err:
                    logger.warning("Erreur lecture de %s: %s", fpath, read_err)

        if combined_meta:
            os.makedirs(filter_dir, exist_ok=True)
            combined_domains = set(combined_meta.keys())
            with open(domains_file, "w", encoding="utf-8") as f:
                for dom in sorted(combined_domains):
                    f.write(f"{dom}\n")

            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(combined_meta, f, indent=2, ensure_ascii=False)

            logger.info(
                "Enregistrement de %d domaines dans %s et %s",
                len(combined_domains),
                domains_file,
                meta_file,
            )
            return combined_domains, combined_meta

    except Exception as e:
        logger.error("Erreur durant le rafraîchissement des listes: %s", e)

    # Fallback si téléchargement échoue mais fichiers de cache existants
    fallback_domains: Set[str] = set()
    fallback_meta: Dict[str, dict] = {}
    if os.path.isfile(meta_file):
        try:
            with open(meta_file, "r", encoding="utf-8", errors="ignore") as f:
                fallback_meta = json.load(f)
            fallback_domains = set(fallback_meta.keys())
        except Exception:
            pass

    if os.path.isfile(domains_file):
        try:
            with open(domains_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        fallback_domains.add(dom)
        except Exception:
            pass

    return fallback_domains, fallback_meta


def load_domain_set(state_dir: str, max_age_days: int = 7) -> Set[str]:
    """Charge le set de domaines bloqués depuis le cache ou effectue une mise à jour.

    Si domains.txt est absent ou plus vieux que max_age_days, télécharge
    les listes distantes, les parse et génère domains.txt.
    Délègue à load_domain_map.

    Args:
        state_dir: Répertoire racine de stockage d'état.
        max_age_days: Durée de validité maximale du cache en jours (défaut: 7).

    Returns:
        Ensemble des domaines bloqués sous forme de set.
    """
    domains, _ = load_domain_map(state_dir, max_age_days)
    return domains


def load_default_whitelist(state_dir: str, max_age_days: int = 7, use_remote: bool = True) -> Set[str]:
    """Charge la whitelist de domaines par défaut (embarquée + distante optionnelle).

    1. Charge le fichier embarqué tracker_filter/data/default_whitelist.txt.
    2. Tente de télécharger ou recharger depuis le cache (filter_lists/allowlist_remote.txt)
       l'allowlist distante avec urllib (timeout 10s, fail-open silencieux).

    Args:
        state_dir: Répertoire racine de stockage d'état.
        max_age_days: Durée de validité maximale du cache en jours (défaut: 7).
        use_remote: Si False, seule la liste embarquée est utilisée.

    Returns:
        Ensemble des domaines légitimes autorisés par défaut.
    """
    domains: Set[str] = set()

    # 1. Chargement des domaines d'infrastructure embarqués
    try:
        import cerbere_paths as _paths
        embedded_path = str(_paths.bundled_file("tracker_filter", "data", "default_whitelist.txt"))
    except ImportError:
        embedded_path = os.path.join(os.path.dirname(__file__), "data", "default_whitelist.txt")
    if os.path.isfile(embedded_path):
        try:
            with open(embedded_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.add(line)
        except Exception as e:
            logger.warning("Erreur lecture default_whitelist.txt embarqué: %s", e)

    if not use_remote:
        return domains

    # 2. Gestion de l'allowlist distante avec cache
    filter_dir = os.path.join(state_dir, "filter_lists")
    remote_cache_file = os.path.join(filter_dir, "allowlist_remote.txt")

    should_download = True
    if os.path.isfile(remote_cache_file):
        try:
            mtime = os.path.getmtime(remote_cache_file)
            age_days = (time.time() - mtime) / 86400.0
            if age_days <= max_age_days:
                should_download = False
        except Exception as e:
            logger.debug("Erreur vérification date cache allowlist distante: %s", e)

    if should_download:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityShield/1.0"}
        for url in ALLOWLIST_URLS:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read()
                os.makedirs(filter_dir, exist_ok=True)
                with open(remote_cache_file, "wb") as f:
                    f.write(content)
                break
            except Exception as e:
                logger.debug("Échec téléchargement allowlist distante %s (fail-open): %s", url, e)

    if os.path.isfile(remote_cache_file):
        try:
            with open(remote_cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.add(line)
        except Exception as e:
            logger.debug("Erreur lecture cache allowlist distant: %s", e)

    return domains

