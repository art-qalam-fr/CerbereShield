"""Renseignement externe sur les domaines bloqués (onglet Filtrage).

Sources utilisées — toutes gratuites, chacune en fail-open :
- RDAP (rdap.org)      : registraire, date de création du domaine
- URLhaus (abuse.ch)   : domaine répertorié dans une base malware
                         (Auth-Key optionnelle via MALWAREBAZAAR_API_KEY)
- Cloudflare DoH       : vraie résolution DNS (le sinkhole répond 0.0.0.0)

Aucune donnée sensible n'est envoyée : seul le nom de domaine est transmis.
"""

import json
import logging
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

logger = logging.getLogger("cerbere.domain_intel")

_TIMEOUT = 6.0
_UA = {"User-Agent": "Cerbere-Security-Shield/1.0 (local security tool)"}


def _http_json(url: str, data: Optional[bytes] = None,
               headers: Optional[Dict[str, str]] = None) -> Optional[dict]:
    """Requête HTTP(S) JSON avec timeout strict — retourne None en cas d'échec."""
    try:
        req = urllib.request.Request(url, data=data, headers=headers or _UA)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        logger.debug("Requête intel échouée (%s) : %s", url.split("/")[2], e)
        return None


def _rdap_info(domain: str) -> Dict[str, Any]:
    """Registraire et date de création via RDAP (remplaçant standard du WHOIS)."""
    # On interroge le domaine registrable (2 derniers labels suffisent en
    # pratique pour la majorité des TLD ; RDAP renvoie 404 sinon — fail-open).
    registrable = ".".join(domain.split(".")[-2:])
    data = _http_json(f"https://rdap.org/domain/{urllib.parse.quote(registrable)}")
    if not data:
        return {"available": False}

    registrar = None
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            # Le nom du registrar est dans le vcard
            vcard = ent.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item[0] == "fn":
                    registrar = item[3]
                    break

    created = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            created = ev.get("eventDate")

    return {
        "available": True,
        "registrar": registrar,
        "created": created,
        "queried": registrable,
    }


def _urlhaus_info(domain: str) -> Dict[str, Any]:
    """Vérifie si le domaine est répertorié dans URLhaus (base malware abuse.ch).

    Depuis mi-2024, abuse.ch exige une Auth-Key (gratuite, liée au compte).
    On réutilise la variable MALWAREBAZAAR_API_KEY — même clé pour toutes
    les API abuse.ch. Sans clé, l'appel échoue en fail-open.
    """
    headers = {**_UA, "Content-Type": "application/x-www-form-urlencoded"}
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if api_key:
        headers["Auth-Key"] = api_key
    data = _http_json(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data=urllib.parse.urlencode({"host": domain}).encode("utf-8"),
        headers=headers,
    )
    if not data:
        return {"available": False}

    status = data.get("query_status")
    if status == "ok":
        urls = data.get("urls", [])
        return {
            "available": True,
            "listed": True,
            "url_count": len(urls),
            "reference": data.get("urlhaus_reference", ""),
        }
    # "no_results" = domaine non répertorié = bon signe
    return {"available": True, "listed": False}


def _resolve_real_ips(domain: str) -> Dict[str, Any]:
    """Résout le domaine via DNS-over-HTTPS Cloudflare — contourne le sinkhole
    local (qui répond 0.0.0.0) pour révéler la vraie adresse du service."""
    data = _http_json(
        "https://cloudflare-dns.com/dns-query?"
        + urllib.parse.urlencode({"name": domain, "type": "A"}),
        headers={"Accept": "application/dns-json", **_UA},
    )
    if not data:
        return {"available": False}

    ips = [
        a["data"] for a in data.get("Answer", [])
        if a.get("type") == 1  # Enregistrements A uniquement
    ]
    return {"available": True, "ips": ips, "status": data.get("Status")}


def inspect_domain(domain: str, local_detail: Optional[dict] = None) -> Dict[str, Any]:
    """Enrichit un domaine bloqué : infos locales + RDAP + URLhaus + DoH.

    Args:
        domain: nom de domaine à analyser (déjà validé/sanitisé en amont).
        local_detail: entrée blocked_detail du sinkhole (règle, sources, compteur…).
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "local": local_detail or {},
        "links": {
            "virustotal": f"https://www.virustotal.com/gui/domain/{urllib.parse.quote(domain)}",
            "urlscan": f"https://urlscan.io/search/#{urllib.parse.quote(domain)}",
            "talos": f"https://talosintelligence.com/reputation_center/lookup?search={urllib.parse.quote(domain)}",
            "safebrowsing": f"https://transparencyreport.google.com/safe-browsing/search?url={urllib.parse.quote(domain)}",
            "whois": f"https://www.whois.com/whois/{urllib.parse.quote(domain)}",
        },
    }

    # Les 3 sources en parallèle — chacune fail-open, jamais d'exception
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_rdap = pool.submit(_rdap_info, domain)
        fut_urlhaus = pool.submit(_urlhaus_info, domain)
        fut_dns = pool.submit(_resolve_real_ips, domain)

        result["rdap"] = fut_rdap.result()
        result["urlhaus"] = fut_urlhaus.result()
        result["dns"] = fut_dns.result()

    logger.info(
        "Inspection domaine %s : rdap=%s urlhaus=%s dns=%s",
        domain,
        result["rdap"].get("available"),
        result["urlhaus"].get("listed") if result["urlhaus"].get("available") else "indispo",
        len(result["dns"].get("ips", [])) if result["dns"].get("available") else "indispo",
    )
    return result
