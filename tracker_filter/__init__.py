"""Module de filtrage DNS et blocage des trackers publicitaires.

Fournit le chargement des règles EasyList / EasyPrivacy et l'interception
DNS via WinDivert pour rediriger les requêtes indésirables vers 0.0.0.0 (sinkhole).
"""

from .dns_sinkhole import DnsSinkhole
from .easylist_parser import (
    ALLOWLIST_URLS,
    download_lists,
    load_default_whitelist,
    load_domain_map,
    load_domain_set,
    parse_domains,
    parse_domains_meta,
)

__all__ = [
    "ALLOWLIST_URLS",
    "DnsSinkhole",
    "download_lists",
    "load_default_whitelist",
    "load_domain_map",
    "load_domain_set",
    "parse_domains",
    "parse_domains_meta",
]

