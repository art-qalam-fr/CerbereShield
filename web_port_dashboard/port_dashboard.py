"""Application FastAPI pour le Web Port Dashboard.

- Scan périodique des ports via RuntimeCollector
- Évaluation du risque via RiskEvaluator
- Endpoint HTTP local :
    - GET /api/ports/current -> snapshot JSON courant
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import csv
import ctypes
import hashlib
import io
import json
import logging
import logging.handlers
import secrets
import threading
import time
from datetime import datetime
import os
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import psutil

# Ajout du chemin pour les imports
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'python'))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # Pour trouver security_audit

import cerbere_paths as paths  # Chemins centralisés (source / PyInstaller frozen)

# Import des modules originaux
try:
    from runtime_collector import RuntimeCollector
    from risk_evaluator import RiskEvaluator
    from history_manager_simple import HistoryManager  # Version simplifiée
    print("[OK] Modules originaux importés avec succès (history_manager_simple)")
except ImportError as e:
    print(f"Erreur import modules dashboard: {e}")
    # Utiliser les modules standalone à la place
    try:
        import runtime_collector_standalone
        import risk_evaluator_standalone
        import history_manager_simple
        RuntimeCollector = runtime_collector_standalone.RuntimeCollector
        RiskEvaluator = risk_evaluator_standalone.RiskEvaluator
        HistoryManager = history_manager_simple.HistoryManager
        print("[OK] Modules standalone importés avec succès")
    except ImportError:
        print("Erreur critique: impossible d'importer les modules")
        # Créer des classes vides pour éviter l'erreur
        class RuntimeCollector:
            def __init__(self, config=None):
                self.config = config or {}
            def get_snapshot(self):
                return {"ports": [], "timestamp": datetime.now().isoformat()}
        
        class RiskEvaluator:
            def __init__(self, config=None):
                self.config = config or {}
            def evaluate(self, data):
                return {"risk_score": 0, "ports": data.get("ports", [])}
        
        class HistoryManager:
            def __init__(self):
                pass
            def save_snapshot(self, data):
                pass
            def save_alert(self, score, message):
                pass
            def delete_alert(self, timestamp: str, message: str) -> bool:
                return False
            def get_history(self, limit=50):
                return []
            def get_alerts(self, limit=50):
                return []

try:
    from intrusion_detector import get_detector
    print("[OK] Module intrusion_detector importé avec succès")
except ImportError as e:
    print(f"Erreur import module détection: {e}")
    try:
        # Essayer avec le chemin complet
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'python'))
        from intrusion_detector import get_detector
        print("[OK] Import intrusion_detector réussi avec chemin complémentaire")
    except ImportError:
        print("[ERR] Erreur critique: impossible d'importer intrusion_detector")
        def get_detector():
            return None


def _require_detector():
    """Retourne le détecteur d'intrusion ou lève une 503 si indisponible."""
    detector = get_detector()
    if detector is None:
        raise HTTPException(status_code=503, detail="Détecteur d'intrusion indisponible")
    return detector


try:
    from reputation import inspect_process_by_pid
    print("[OK] Module reputation importé avec succès")
except ImportError as e:
    try:
        from web_port_dashboard.reputation import inspect_process_by_pid
        print("[OK] Module web_port_dashboard.reputation importé avec succès")
    except ImportError:
        print(f"[ERR] Erreur import module reputation: {e}")
        inspect_process_by_pid = None

try:
    from tracker_filter import DnsSinkhole, load_domain_set, load_domain_map, load_default_whitelist
    from domain_intel import inspect_domain
    print("[OK] Module tracker_filter importé avec succès")
except ImportError as e:
    print(f"Erreur import module tracker_filter: {e}")
    DnsSinkhole = None
    load_domain_set = None
    load_domain_map = None
    load_default_whitelist = None
    inspect_domain = None

try:
    from tracker_filter.list_manager import AdblockListManager, LIST_REGISTRY
    from tracker_filter.list_updater import ListUpdateScheduler, update_all_lists
    print("[OK] Module tracker_filter.list_manager/list_updater importé avec succès")
except ImportError as e:
    print(f"Module adblock list_manager/list_updater indisponible: {e}")
    AdblockListManager = None
    LIST_REGISTRY = {}
    ListUpdateScheduler = None
    update_all_lists = None

try:
    from parental_control.pin_manager import PinManager
    from parental_control.lists_manager import ListsManager
    from parental_control.quota_tracker import QuotaTracker
    from parental_control.rules_engine import RulesEngine
    try:
        from parental_control.cookies_scanner import CookieScanner
    except ImportError:
        CookieScanner = None
    print("[OK] Module parental_control importé avec succès")
except ImportError as e:
    print(f"Erreur import module parental_control: {e}")
    PinManager = None
    ListsManager = None
    QuotaTracker = None
    RulesEngine = None
    CookieScanner = None

try:
    from notifier import send_external_alert
    print("[OK] Module notifier importé avec succès")
except ImportError as e:
    try:
        from web_port_dashboard.notifier import send_external_alert
        print("[OK] Module web_port_dashboard.notifier importé avec succès")
    except ImportError:
        print(f"[ERR] Erreur import module notifier: {e}")
        def send_external_alert(cfg, score, message):
            return False




SCAN_INTERVAL_SECONDS_DEFAULT = 30  # 30 s par défaut, surchargeable via config.yml
ALERT_THRESHOLD = 70

# ============= JOURNALISATION DETAILLEE (logs/cerbere.log) =============
_LOGS_DIR = paths.logs_dir()
try:
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    _file_handler = logging.handlers.RotatingFileHandler(
        _LOGS_DIR / "cerbere.log",
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    _file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
    ))
    logging.getLogger().addHandler(_file_handler)
    logging.getLogger().setLevel(logging.INFO)
except Exception:
    pass

logger = logging.getLogger("cerbere.dashboard")

app = FastAPI(title="Cerbere Security Shield", docs_url=None, redoc_url=None)

# Assets statiques (index.html, images du branding, favicon)
_static_dir = paths.module_dir() / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# CORS limité : uniquement usage local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


_snapshot: Dict[str, Any] | None = None
_snapshot_lock = asyncio.Lock()
_scan_task: "asyncio.Task | None" = None
_watchdog_task: "asyncio.Task | None" = None
_sinkhole: Any | None = None
_adblock_manager: Any | None = None
_list_scheduler: Any | None = None

# Contrôle parental / domestique (instanciés à la demande)
_pin_manager: Any | None = None
_lists_manager: Any | None = None
_quota_tracker: Any | None = None
_rules_engine: Any | None = None
_cookie_scanner: Any | None = None
# Sessions PIN courtes (token -> timestamp d'expiration), 10 minutes
_parental_sessions: Dict[str, float] = {}
_PARENTAL_SESSION_SECONDS = 600


def _state_dir() -> Path:
    return paths.state_dir()


def _get_pin_manager():
    global _pin_manager
    if _pin_manager is None and PinManager is not None:
        _pin_manager = PinManager()
    return _pin_manager


def _get_rules_engine():
    """Instancie le moteur de règles + listes + quotas (lazy, thread-safe GIL)."""
    global _lists_manager, _quota_tracker, _rules_engine
    if _rules_engine is None and RulesEngine is not None and ListsManager is not None:
        _lists_manager = ListsManager(state_dir=str(_state_dir()))
        _quota_tracker = QuotaTracker(state_dir=str(_state_dir()))
        _rules_engine = RulesEngine(_lists_manager, _quota_tracker, str(_state_dir()))
    return _rules_engine


def _get_adblock_manager():
    """Instancie le gestionnaire de listes adblock (lazy)."""
    global _adblock_manager
    if _adblock_manager is None and AdblockListManager is not None:
        _adblock_manager = AdblockListManager(state_dir=str(_state_dir()))
    return _adblock_manager


def _load_combined_domain_map(state_dir: str) -> Tuple[set, Dict[str, dict]]:
    """Domaines bloqués = listes EasyList historiques ∪ listes adblock activées."""
    if load_domain_map is not None:
        domaines, domain_meta = load_domain_map(state_dir)
    else:
        domaines = load_domain_set(state_dir)
        domain_meta = {}
    mgr = _get_adblock_manager()
    if mgr is not None:
        try:
            extra = mgr.get_domains()
            for dom in extra:
                if dom not in domaines:
                    domain_meta.setdefault(dom, {"sources": [], "rule": ""})
        except Exception as e:
            logger.warning("Fusion listes adblock impossible : %s", e)
            extra = set()
        domaines = domaines | extra
    return domaines, domain_meta


def _rebuild_sinkhole_domains() -> int:
    """Recharge à chaud l'ensemble des domaines bloqués du sinkhole actif."""
    if _sinkhole is None:
        return 0
    domaines, domain_meta = _load_combined_domain_map(str(_state_dir()))
    _sinkhole.domaines = domaines
    if hasattr(_sinkhole, "domain_meta"):
        _sinkhole.domain_meta = domain_meta
    return len(domaines)


def _get_cookie_scanner():
    global _cookie_scanner
    if _cookie_scanner is None and CookieScanner is not None:
        _cookie_scanner = CookieScanner()
    return _cookie_scanner


def _pin_ok(request: Request) -> bool:
    """Vérifie la session PIN parentale (cookie cerbere_parental, 10 min)."""
    token = request.cookies.get("cerbere_parental")
    if not token:
        return False
    exp = _parental_sessions.get(token, 0.0)
    if time.time() > exp:
        _parental_sessions.pop(token, None)
        return False
    # Sliding expiration : prolonge la session de 10 min à chaque action.
    _parental_sessions[token] = time.time() + _PARENTAL_SESSION_SECONDS
    return True


def _require_pin(request: Request) -> None:
    """Lève 403 si aucune session PIN valide (verify via /api/parental/verify)."""
    if not _pin_ok(request):
        raise HTTPException(
            status_code=403,
            detail="PIN parental requis — vérifiez-le via l'onglet Contrôle parental.",
        )


class HardeningPort(BaseModel):
    """Représente un port sélectionné pour durcissement."""

    port: int
    protocol: str
    risk: str | None = None


class HardeningPlanRequest(BaseModel):
    """Payload pour la génération d'un plan de durcissement."""

    ports: List[HardeningPort]
    action: str | None = "harden"  # "harden" (blocage) ou "release" (libération)


class AlertDeleteRequest(BaseModel):
    """Payload pour la suppression manuelle d'une alerte."""

    timestamp: str
    message: str


class ProtectionState(BaseModel):
    """État global de protection exposé à l’UI / systray.

    - enabled: True si un plan de durcissement est considéré actif.
    - last_change: timestamp ISO (UTC) de la dernière mise à jour.
    """

    enabled: bool = False
    last_change: str | None = None


class PortSelectionItem(BaseModel):
    """Élément de configuration de sélection de ports.

    Représente un port/protocole sélectionné dans le dashboard.
    """

    port: int
    protocol: str


class PortSelectionConfig(BaseModel):
    """Configuration complète de sélection de ports persistant côté backend."""

    ports: List[PortSelectionItem] = []


def _default_config() -> Dict[str, Any]:
    """Configuration par défaut pour le dashboard.

    Utilisée si aucun fichier de configuration n'est trouvé.
    """

    return {
        "debug": False,
        "critical_ports": [22, 80, 443, 3389, 3306, 5432],
        "allowed_ports": [],  # à alimenter plus tard (MCP, n8n, etc.)
        "allowed_processes": [],  # processus autorisés à écouter (noms minuscules)
        "scan_interval_seconds": SCAN_INTERVAL_SECONDS_DEFAULT,
    }


def _load_config() -> Dict[str, Any]:
    """Chargement de la configuration.

    Ordre de recherche (premier trouvé utilisé) :
    1. web_port_dashboard/config.yml
    2. security_audit/config.yml (pour rester cohérent avec l'audit si présent)
    3. configuration par défaut en dur.
    """

    base = _default_config()

    # 1. Config spécifique au dashboard
    dashboard_cfg_path = paths.config_file()

    # 2. Config globale d'audit éventuellement partagée
    security_audit_cfg_path = paths.config_file(package="security_audit")

    cfg_file: Path | None = None
    if dashboard_cfg_path.is_file():
        cfg_file = dashboard_cfg_path
    elif security_audit_cfg_path.is_file():
        cfg_file = security_audit_cfg_path

    if not cfg_file:
        return base

    try:
        with cfg_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        # En cas de problème de parsing, on revient sur la config par défaut
        return base

    # On fusionne pour garder des valeurs par défaut raisonnables
    merged = dict(base)
    merged.update({
        k: v
        for k, v in data.items()
        if k in SETTINGS_KEYS
    })
    return merged


def _config_file_path() -> Path:
    return paths.config_file()


def _save_config(cfg: Dict[str, Any]) -> None:
    """Persiste la configuration dans web_port_dashboard/config.yml."""
    _config_file_path().write_text(
        yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


_runtime_config: Dict[str, Any] | None = None


def _runtime_cfg() -> Dict[str, Any]:
    """Configuration partagée en mémoire (mutations répercutées à chaud)."""
    global _runtime_config
    if _runtime_config is None:
        _runtime_config = _load_config()
    return _runtime_config


# ============= VERROUILLAGE APPLICATIF (T45) =============

_sessions: set = set()

# Endpoints de MODIFICATION protégés par le verrou. Les lectures (GET),
# le déverrouillage et les endpoints utilisés par le systray
# (/api/alerts, /api/protection/state, /api/filter/start|stop) restent ouverts.
_GUARDED_POST_PATHS = {
    "/api/alerts/delete",
    "/api/hardening/plan",
    "/api/audit/generate-plan",
    "/api/intrusion/unban",
    "/api/intrusion/whitelist",
    "/api/intrusion/start",
    "/api/intrusion/stop",
    "/api/intrusion/test",
    "/api/filter/whitelist",
    "/api/filter/whitelist/reset",
    "/api/protection/state",
}
_GUARDED_PREFIXES = ("/api/settings", "/api/parental", "/api/domestic")


def _access_cfg() -> Dict[str, Any]:
    acc = _runtime_cfg().get("access")
    return acc if isinstance(acc, dict) else {}


def _access_enabled() -> bool:
    # Désactivable via config.yml (access.enabled: false) ou en tests.
    if "pytest" in sys.modules or os.environ.get("CERBERE_DISABLE_LOCK") == "1":
        return False
    return bool(_access_cfg().get("enabled", True))


def _is_unlocked(request: Request) -> bool:
    return request.cookies.get("cerbere_session") in _sessions


@app.middleware("http")
async def _auth_guard(request: Request, call_next):
    path = request.url.path
    if _access_enabled() and request.method in ("POST", "PUT", "DELETE"):
        guarded = path in _GUARDED_POST_PATHS or path.startswith(_GUARDED_PREFIXES)
        if guarded and not _is_unlocked(request):
            return JSONResponse(
                {"detail": "Application verrouillée — déverrouillez via l'écran d'accueil."},
                status_code=401,
            )
    return await call_next(request)


def _verify_windows_password(password: str) -> bool:
    """Demande à Windows si le mot de passe correspond à la session en cours
    (LogonUser — rien n'est stocké)."""
    if os.name != "nt" or not password:
        return False
    try:
        advapi32 = ctypes.windll.advapi32
        handle = ctypes.c_void_p()
        ok = advapi32.LogonUserW(
            ctypes.c_wchar_p(os.getlogin()),
            ctypes.c_wchar_p("."),
            ctypes.c_wchar_p(password),
            3,  # LOGON32_LOGON_NETWORK
            0,  # LOGON32_PROVIDER_DEFAULT
            ctypes.byref(handle),
        )
        if ok:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
    except Exception:
        pass
    return False


def _hash_app_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100_000
    ).hex()


def _verify_app_password(password: str) -> bool:
    acc = _access_cfg()
    salt = acc.get("app_password_salt")
    expected = acc.get("app_password_hash")
    if not salt or not expected or not password:
        return False
    return secrets.compare_digest(_hash_app_password(password, salt), expected)


class UnlockRequest(BaseModel):
    password: str = Field(default="")


# Anti brute-force : après 5 échecs, verrouillage temporaire croissant.
# Protège aussi le compte Windows (LogonUserW) contre le verrouillage
# par tentatives répétées.
_unlock_failures = {"count": 0, "locked_until": 0.0}


@app.post("/api/unlock")
async def unlock(req: UnlockRequest, response: Response) -> Dict[str, Any]:
    """Déverrouille l'application : vérifie le mot de passe de session
    Windows (défaut) ou le mot de passe dédié de l'application."""
    now = time.time()
    if now < _unlock_failures["locked_until"]:
        wait = int(_unlock_failures["locked_until"] - now) + 1
        logger.warning("Déverrouillage refusé : trop de tentatives (%ss restantes)", wait)
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessayez dans {wait} s.",
        )

    acc = _access_cfg()
    method = acc.get("method", "windows")

    # Premier lancement en méthode « app » : aucun hash configuré → le premier
    # mot de passe soumis devient le mot de passe dédié (postes sans mot de
    # passe Windows, ex. Windows Hello).
    first_run = method == "app" and not acc.get("app_password_hash")
    if first_run:
        new_pwd = (req.password or "").strip()
        if len(new_pwd) < 4:
            raise HTTPException(
                status_code=400,
                detail="Choisissez un mot de passe d'au moins 4 caractères.",
            )
        salt = secrets.token_hex(16)
        acc["app_password_salt"] = salt
        acc["app_password_hash"] = _hash_app_password(new_pwd, salt)
        cfg = _runtime_cfg()
        cfg["access"] = acc
        _save_config(cfg)
        logger.info("Mot de passe dédié initialisé au premier lancement")

    ok = first_run or (
        _verify_app_password(req.password)
        if method == "app"
        else _verify_windows_password(req.password)
    )
    if not ok:
        _unlock_failures["count"] += 1
        if _unlock_failures["count"] >= 5:
            # Backoff croissant : 30s, puis double à chaque palier de 5 échecs
            delay = min(30 * (1 << (_unlock_failures["count"] // 5 - 1)), 600)
            _unlock_failures["locked_until"] = time.time() + delay
            logger.warning(
                "Déverrouillage verrouillé %ss après %d échecs",
                delay, _unlock_failures["count"],
            )
        logger.warning("Tentative de déverrouillage refusée (méthode=%s)", method)
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    _unlock_failures["count"] = 0
    _unlock_failures["locked_until"] = 0.0
    token = secrets.token_urlsafe(32)
    _sessions.add(token)
    logger.info("Application déverrouillée (méthode=%s)", method)
    response.set_cookie("cerbere_session", token, httponly=True, samesite="lax")
    return {"success": True}


@app.post("/api/lock")
async def lock(request: Request) -> Dict[str, Any]:
    """Re-verrouille l'application (invalide la session courante)."""
    token = request.cookies.get("cerbere_session")
    if token:
        _sessions.discard(token)
    resp = JSONResponse({"success": True})
    resp.delete_cookie("cerbere_session")
    return resp


@app.get("/api/auth/status")
async def auth_status(request: Request) -> Dict[str, Any]:
    """Indique si l'application est déverrouillée et la méthode d'accès."""
    enabled = _access_enabled()
    acc = _access_cfg()
    return {
        "enabled": enabled,
        "unlocked": (not enabled) or _is_unlocked(request),
        "method": acc.get("method", "windows"),
        "needs_setup": acc.get("method", "windows") == "app"
        and not acc.get("app_password_hash"),
    }


# ============= PARAMETRES (T41) =============

SETTINGS_KEYS = {
    "debug", "critical_ports", "allowed_ports", "allowed_processes",
    "scan_interval_seconds", "notify_grace_seconds",
    "filter_autostart", "use_remote_whitelist",
    "alert_email", "webhook_url", "external_alerts_enabled",
    "external_min_severity", "smtp_host", "smtp_port", "smtp_user",
    "smtp_password", "access", "ui_language",
}
_SECRET_SETTING_KEYS = {"smtp_password", "app_password_hash", "app_password_salt"}


def _public_settings() -> Dict[str, Any]:
    """Config lisible par l'UI — jamais de secrets en clair."""
    cfg = dict(_runtime_cfg())
    for k in _SECRET_SETTING_KEYS:
        if cfg.get(k):
            cfg[k] = "•••"
    acc = cfg.get("access")
    if isinstance(acc, dict):
        acc = dict(acc)
        for k in ("app_password_hash", "app_password_salt"):
            if acc.get(k):
                acc[k] = "•••"
        acc["has_app_password"] = bool(_access_cfg().get("app_password_hash"))
        cfg["access"] = acc
    return cfg


@app.get("/api/settings")
async def get_settings() -> Dict[str, Any]:
    return _public_settings()


_UI_LANGUAGES = {"fr", "en", "de", "es"}


@app.get("/api/ui/language")
async def get_ui_language() -> Dict[str, Any]:
    """Langue de l'interface — lecture libre, persistée dans config.yml."""
    lang = str(_runtime_cfg().get("ui_language") or "fr")
    if lang not in _UI_LANGUAGES:
        lang = "fr"
    return {"language": lang, "available": sorted(_UI_LANGUAGES)}


@app.post("/api/ui/language")
async def set_ui_language(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Change la langue de l'interface (preference d'affichage, non verrouillee)."""
    lang = str(payload.get("language") or "fr").strip().lower()
    if lang not in _UI_LANGUAGES:
        lang = "fr"
    cfg = _runtime_cfg()
    cfg["ui_language"] = lang
    _save_config(cfg)
    return {"language": lang}


@app.put("/api/settings")
async def update_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Met à jour les paramètres connus et les persiste dans config.yml."""
    cfg = _runtime_cfg()
    acc = dict(_access_cfg())

    if "scan_interval_seconds" in payload:
        cfg["scan_interval_seconds"] = max(5, min(3600, int(payload["scan_interval_seconds"])))
    for key in ("critical_ports", "allowed_ports"):
        if key in payload:
            cfg[key] = sorted({int(p) for p in payload[key]})
    if "allowed_processes" in payload:
        cfg["allowed_processes"] = sorted({str(p).strip().lower() for p in payload["allowed_processes"] if str(p).strip()})
    for key in ("notify_grace_seconds",):
        if key in payload:
            cfg[key] = max(0, min(600, int(payload[key])))
    for key in ("filter_autostart", "use_remote_whitelist", "external_alerts_enabled"):
        if key in payload:
            cfg[key] = bool(payload[key])
    for key in ("alert_email", "webhook_url", "smtp_host", "smtp_user"):
        if key in payload:
            cfg[key] = str(payload[key]).strip()
    if "smtp_port" in payload:
        cfg["smtp_port"] = int(payload["smtp_port"])
    if "smtp_password" in payload and payload["smtp_password"] not in ("", "•••"):
        cfg["smtp_password"] = str(payload["smtp_password"])
    if "external_min_severity" in payload:
        cfg["external_min_severity"] = max(0, min(100, int(payload["external_min_severity"])))

    access_payload = payload.get("access") or {}
    if isinstance(access_payload, dict):
        if "enabled" in access_payload:
            acc["enabled"] = bool(access_payload["enabled"])
        if access_payload.get("method") in ("windows", "app"):
            acc["method"] = access_payload["method"]
        new_pwd = access_payload.get("new_app_password")
        if new_pwd:
            salt = secrets.token_hex(16)
            acc["app_password_salt"] = salt
            acc["app_password_hash"] = _hash_app_password(str(new_pwd), salt)
    cfg["access"] = acc

    # Application à chaud des réglages à effet immédiat
    if "filter_autostart" in payload:
        _save_filter_state({"enabled": cfg["filter_autostart"]})
    if "notify_grace_seconds" in payload and _sinkhole is not None:
        try:
            _sinkhole.notify_grace_seconds = cfg["notify_grace_seconds"]
        except Exception:
            pass

    _save_config(cfg)
    logger.info("Paramètres mis à jour et persistés : %s", sorted(payload.keys()))
    return _public_settings()


def _get_state_file() -> Path:
    """Retourne le chemin du fichier d’état de protection.

    Stocké dans web_port_dashboard/state/protection_state.json
    """

    state_dir = paths.state_dir()
    return state_dir / "protection_state.json"


def _get_selection_file() -> Path:
    """Retourne le chemin du fichier de configuration de sélection de ports.

    Stocké dans web_port_dashboard/state/selection_config.json
    """

    state_dir = paths.state_dir()
    return state_dir / "selection_config.json"


def _load_protection_state() -> ProtectionState:
    """Charge l’état de protection depuis le fichier JSON (ou valeurs par défaut)."""

    state_file = _get_state_file()
    if not state_file.is_file():
        return ProtectionState()

    try:
        data = json.loads(state_file.read_text(encoding="utf-8") or "{}")
        return ProtectionState(**data)
    except Exception:
        # En cas de fichier corrompu, on repart sur un état neutre
        return ProtectionState()


def _save_protection_state(state: ProtectionState) -> None:
    """Sauvegarde l’état de protection dans le fichier JSON dédié."""

    state_file = _get_state_file()
    payload = state.dict()
    state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _sync_protection_state(enabled: bool) -> None:
    state = _load_protection_state()
    state.enabled = enabled
    state.last_change = datetime.utcnow().isoformat() + "Z"
    _save_protection_state(state)


def _load_port_selection() -> PortSelectionConfig:
    """Charge la configuration de sélection de ports depuis le fichier JSON."""

    selection_file = _get_selection_file()
    if not selection_file.is_file():
        return PortSelectionConfig()

    try:
        data = json.loads(selection_file.read_text(encoding="utf-8") or "{}")
        return PortSelectionConfig(**data)
    except Exception:
        # En cas de fichier corrompu, repartir sur une config vide
        return PortSelectionConfig()


def _save_port_selection(config: PortSelectionConfig) -> None:
    """Sauvegarde la configuration de sélection de ports."""

    selection_file = _get_selection_file()
    payload = config.dict()
    selection_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _get_filter_state_file() -> Path:
    """Retourne le chemin du fichier d'état du filtrage trackers."""
    state_dir = paths.state_dir()
    return state_dir / "filter_state.json"


def _get_filter_whitelist_file() -> Path:
    """Retourne le chemin du fichier de whitelist du filtrage trackers."""
    state_dir = paths.state_dir()
    return state_dir / "filter_whitelist.json"


def _load_filter_state() -> Dict[str, Any]:
    """Charge l'état du filtrage (ex: enabled: bool)."""
    f = _get_filter_state_file()
    if not f.is_file():
        return {"enabled": False}
    try:
        data = json.loads(f.read_text(encoding="utf-8") or "{}")
        if isinstance(data, dict):
            return data
        return {"enabled": False}
    except Exception:
        return {"enabled": False}


def _save_filter_state(data: Dict[str, Any]) -> None:
    """Persiste l'état du filtrage dans filter_state.json."""
    f = _get_filter_state_file()
    f.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_filter_whitelist_config() -> Dict[str, List[str]]:
    """Charge la configuration de whitelist (custom et disabled_defaults).

    Garantit la compatibilité avec un fichier existant contenant soit :
    - Une liste JSON de domaines : ["domaine1", ...] (ancien format user)
    - Un dictionnaire JSON : {"custom": [...], "disabled_defaults": [...]}
    La clé 'custom' est toujours initialisée même si absente.
    """
    f = _get_filter_whitelist_file()
    if not f.is_file():
        return {"custom": [], "disabled_defaults": []}
    try:
        content = f.read_text(encoding="utf-8").strip()
        if not content:
            return {"custom": [], "disabled_defaults": []}
        data = json.loads(content)
        if isinstance(data, list):
            custom = sorted(list({str(d).lower().strip() for d in data if str(d).strip()}))
            return {"custom": custom, "disabled_defaults": []}
        elif isinstance(data, dict):
            raw_custom = data.get("custom", [])
            if not isinstance(raw_custom, list):
                raw_custom = []
            raw_disabled = data.get("disabled_defaults", [])
            if not isinstance(raw_disabled, list):
                raw_disabled = []
            custom = sorted(list({str(d).lower().strip() for d in raw_custom if str(d).strip()}))
            disabled = sorted(list({str(d).lower().strip() for d in raw_disabled if str(d).strip()}))
            return {"custom": custom, "disabled_defaults": disabled}
        return {"custom": [], "disabled_defaults": []}
    except Exception as e:
        print(f"Erreur lecture filter_whitelist.json: {e}")
        return {"custom": [], "disabled_defaults": []}


def _save_filter_whitelist_config(custom: List[str], disabled_defaults: List[str]) -> None:
    """Persiste la configuration de whitelist dans filter_whitelist.json."""
    f = _get_filter_whitelist_file()
    data = {
        "custom": sorted(list({str(d).lower().strip() for d in custom if str(d).strip()})),
        "disabled_defaults": sorted(list({str(d).lower().strip() for d in disabled_defaults if str(d).strip()})),
    }
    f.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_filter_whitelist() -> List[str]:
    """Charge la liste custom des domaines autorisés par l'utilisateur."""
    return _load_filter_whitelist_config().get("custom", [])


def _save_filter_whitelist(whitelist: List[str]) -> None:
    """Persiste la liste des domaines personnalisés tout en conservant disabled_defaults."""
    cfg = _load_filter_whitelist_config()
    _save_filter_whitelist_config(whitelist, cfg.get("disabled_defaults", []))


def _get_default_whitelist(state_dir: Optional[str] = None) -> Set[str]:
    """Charge l'ensemble des domaines autorisés par défaut (embarqués + distants)."""
    if state_dir is None:
        state_dir = str(paths.state_dir())
    if load_default_whitelist is not None:
        try:
            use_remote = bool(_runtime_cfg().get("use_remote_whitelist", True))
            return load_default_whitelist(state_dir, use_remote=use_remote)
        except Exception as e:
            print(f"Erreur chargement default whitelist: {e}")
    return set()


def _get_effective_whitelist(state_dir: Optional[str] = None) -> Set[str]:
    """Calcule l'ensemble effectif de la whitelist : (defaults ∪ custom) − disabled_defaults."""
    defaults = _get_default_whitelist(state_dir)
    cfg = _load_filter_whitelist_config()
    custom = set(cfg.get("custom", []))
    disabled = set(cfg.get("disabled_defaults", []))
    return (defaults | custom) - disabled



class FilterWhitelistRequest(BaseModel):
    """Payload pour gérer la whitelist de filtrage trackers."""
    domain: str
    action: str = Field(..., pattern="^(add|remove)$")


@app.get("/api/protection/state")
async def get_protection_state() -> Dict[str, Any]:
    """Retourne l’état global de protection.

    Utilisé par le dashboard et, plus tard, par l’appli systray.
    """

    state = _load_protection_state()
    return state.dict()


class ProtectionStateUpdate(BaseModel):
    """Payload minimal pour mettre à jour l’état de protection."""

    enabled: bool


@app.post("/api/protection/state")
async def set_protection_state(update: ProtectionStateUpdate) -> Dict[str, Any]:
    """Met à jour l’état de protection (ON/OFF).

    Met aussi à jour le timestamp `last_change`.
    """

    state = _load_protection_state()
    state.enabled = update.enabled
    state.last_change = datetime.utcnow().isoformat() + "Z"
    _save_protection_state(state)
    return state.dict()


@app.get("/api/config/selection")
async def get_port_selection() -> Dict[str, Any]:
    """Retourne la configuration courante de sélection de ports.

    Cette API sera utilisée par le dashboard pour restaurer l'état des cases à cocher
    et par d'autres composants (systray, scripts) si nécessaire.
    """

    cfg = _load_port_selection()
    return cfg.dict()


@app.post("/api/config/selection")
async def set_port_selection(config: PortSelectionConfig) -> Dict[str, Any]:
    """Met à jour et persiste la configuration de sélection de ports."""

    # Normalisation minimale du protocole
    normalized_ports = [
        PortSelectionItem(port=item.port, protocol=item.protocol.lower())
        for item in config.ports
    ]
    cfg = PortSelectionConfig(ports=normalized_ports)
    _save_port_selection(cfg)
    return cfg.dict()


# Dédup sécurité : même (message) réécrit au plus 1 fois / 5 min —
# filet contre les doublons IPv4/IPv6 (même message, clés d'anomalie
# différentes) et les races entre threads (sinkhole, intrusion, scan).
# La clé n'inclut PAS le score : une fluctuation 83→81 ne doit pas
# produire une nouvelle alerte.
_alert_dedup: Dict[str, float] = {}
_alert_dedup_lock = threading.Lock()
_ALERT_DEDUP_SECONDS = 300.0

# Hystérésis de l'alerte "score de risque élevé" : module-level car
# _scan_loop peut être redémarré par le watchdog sans perdre l'état.
_score_alert_state = {"active": False}


def _record_alert(history, score, message) -> None:
    """Journalise une alerte et déclenche l'envoi externe (email/webhook)
    en tâche de fond — jamais bloquant, jamais d'exception propagée."""
    now = time.time()
    with _alert_dedup_lock:
        last = _alert_dedup.get(message, 0.0)
        if now - last < _ALERT_DEDUP_SECONDS:
            logger.debug("Alerte dédupliquée ignorée : %s", message)
            return
        _alert_dedup[message] = now
        # Purge occasionnelle des entrées expirées
        if len(_alert_dedup) > 500:
            for k in [k for k, t in _alert_dedup.items() if now - t >= _ALERT_DEDUP_SECONDS]:
                _alert_dedup.pop(k, None)

    history.save_alert(score, message)
    logger.warning("ALERTE [%s/100] %s", score, message)
    try:
        cfg = _runtime_cfg()
        if cfg.get("external_alerts_enabled", True):
            threading.Thread(
                target=send_external_alert,
                args=(dict(cfg), score, message),
                daemon=True,
            ).start()
    except Exception:
        pass


async def _scan_loop(collector, evaluator, history, interval: int) -> None:
    """Boucle principale de scan exécutée dans une tâche dédiée."""
    global _snapshot
    while True:
        try:
            # collector.get_snapshot() est synchrone (psutil) → thread séparé
            network_data = await asyncio.to_thread(collector.get_snapshot)
            evaluated = evaluator.evaluate(network_data)

            async with _snapshot_lock:
                _snapshot = evaluated

            # Historisation
            history.save_snapshot(evaluated)

            # Gestion des alertes — hystérésis : l'alerte de score ne tire
            # qu'à la transition franchissant le seuil, et se réarme sous 60.
            # Sinon, un score durablement haut notifierait toutes les 5 min.
            risk_score = evaluated.get("risk_score", 0)
            if risk_score >= ALERT_THRESHOLD:
                if not _score_alert_state["active"]:
                    _score_alert_state["active"] = True
                    _record_alert(
                        history, risk_score,
                        f"Score de risque élevé détecté : {risk_score}/100"
                    )
            elif risk_score < 60:
                _score_alert_state["active"] = False

            # Alertes d'anomalie processus (indépendantes du score global)
            for alert in evaluated.get("alerts", []):
                severity_score = 90 if alert.get("severity") == "critical" else 50
                _record_alert(
                    history, severity_score,
                    alert.get("message", "Anomalie processus détectée")
                )

        except Exception as e:
            print(f"Erreur lors du scan périodique : {e}")

        # Intervalle relu à chaque cycle → modification à chaud via Paramètres
        await asyncio.sleep(int(_runtime_cfg().get("scan_interval_seconds", interval)))


async def _watchdog(collector, evaluator, history, interval: int) -> None:
    """Vérifie que la tâche de scan reste vivante et la redémarre en cas d'échec."""
    global _scan_task
    while True:
        await asyncio.sleep(10)
        if _scan_task is None:
            continue
        if _scan_task.done():
            exc = _scan_task.exception()
            if exc:
                print(f"Watchdog : tâche de scan terminée avec erreur : {exc}")
            else:
                print("Watchdog : tâche de scan terminée normalement, redémarrage.")
            _scan_task = asyncio.create_task(
                _scan_loop(collector, evaluator, history, interval)
            )


@app.on_event("startup")
async def startup_event() -> None:
    """Démarre le scan périodique et le watchdog au lancement de l'app."""
    global _scan_task, _watchdog_task

    config = _runtime_cfg()
    interval = int(config.get("scan_interval_seconds", SCAN_INTERVAL_SECONDS_DEFAULT))

    collector = RuntimeCollector(config)
    evaluator = RiskEvaluator(
        config,
        state_dir=str(paths.state_dir()),
    )
    history = HistoryManager()

    # Premier scan immédiat (non bloquant)
    try:
        network_data = await asyncio.to_thread(collector.get_snapshot)
        evaluated = evaluator.evaluate(network_data, record_anomalies=False)
        async with _snapshot_lock:
            _snapshot = evaluated
        print("Premier scan effectué avec succès")
    except Exception as e:
        print(f"Erreur lors du premier scan : {e}")

    _scan_task = asyncio.create_task(_scan_loop(collector, evaluator, history, interval))
    _watchdog_task = asyncio.create_task(_watchdog(collector, evaluator, history, interval))
    print("Serveur démarré avec scan périodique et watchdog activés")

    # Autodémarrage de la détection d'intrusion (thread non bloquant)
    try:
        detector = get_detector()
        if detector is not None:
            if not getattr(detector, "running", False):
                detector.start_monitoring()
            detector.alert_callback = lambda score, msg: _record_alert(history, score, msg)
            print("Détection d'intrusion démarrée automatiquement")
    except Exception as e:
        print(f"Impossible de démarrer la détection d'intrusion : {e}")

    # Autodémarrage du filtrage DNS & Trackers
    global _sinkhole
    try:
        filter_state = _load_filter_state()
        if filter_state.get("enabled", False):
            if DnsSinkhole is not None and (load_domain_map is not None or load_domain_set is not None):
                state_dir = paths.state_dir()
                domaines, domain_meta = await asyncio.to_thread(
                    _load_combined_domain_map, str(state_dir)
                )
                whitelist = _get_effective_whitelist(str(state_dir))
                _sinkhole = DnsSinkhole(
                    domaines=domaines,
                    whitelist=whitelist,
                    alert_callback=lambda s, m: _record_alert(history, s, m),
                    domain_meta=domain_meta,
                    notify_grace_seconds=float(config.get("notify_grace_seconds", 60)),
                    state_dir=str(state_dir),
                    rule_resolver=(
                        _get_rules_engine().decide if _get_rules_engine() is not None else None
                    ),
                )
                _sinkhole.start()
                print(f"Filtrage DNS & Trackers démarré automatiquement ({len(domaines)} domaines)")
            else:
                print("Filtrage trackers activé mais module tracker_filter ou pydivert indisponible")
    except (ImportError, Exception) as e:
        print(f"Impossible d'initialiser le filtrage DNS & Trackers : {e}")
        _sinkhole = None

    # Planificateur de mise à jour des listes (adblock + parental), non bloquant
    global _list_scheduler
    try:
        if ListUpdateScheduler is not None:
            _list_scheduler = ListUpdateScheduler(state_dir=str(_state_dir()))
            _list_scheduler.start()
    except Exception as e:
        print(f"Planificateur de mise à jour des listes non démarré : {e}")
        _list_scheduler = None


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Annule proprement le scan, le watchdog et le filtrage à l'arrêt du serveur."""
    global _scan_task, _watchdog_task, _sinkhole, _list_scheduler
    if _list_scheduler is not None:
        try:
            _list_scheduler.stop()
        except Exception:
            pass
    if _sinkhole is not None:
        try:
            if getattr(_sinkhole, "running", False):
                _sinkhole.stop()
        except Exception as e:
            print(f"Erreur lors de l'arrêt du sinkhole DNS : {e}")

    tasks_to_cancel = [t for t in (_scan_task, _watchdog_task) if t is not None]
    for task in tasks_to_cancel:
        task.cancel()
    await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
    print("Serveur stoppé, tâches de scan et watchdog annulées")


@app.get("/api/history")
async def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retourne l'historique des snapshots de sécurité."""
    try:
        history = HistoryManager()
        return history.get_history(limit=limit)
    except Exception as e:
        print(f"Erreur get_history: {e}")
        # Retourner un historique vide en cas d'erreur
        return []

@app.get("/api/alerts")
async def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retourne l'historique des alertes de sécurité."""
    try:
        history = HistoryManager()
        return history.get_alerts(limit=limit)
    except Exception as e:
        print(f"Erreur get_alerts: {e}")
        # Retourner une liste vide en cas d'erreur
        return []


@app.post("/api/alerts/delete")
async def delete_alert(req: AlertDeleteRequest) -> Dict[str, Any]:
    """Supprime une alerte par timestamp et message."""
    try:
        history = HistoryManager()
        deleted = history.delete_alert(req.timestamp, req.message)
        return {"success": True, "deleted": deleted}
    except Exception as e:
        print(f"Erreur delete_alert: {e}")
        return {"success": False, "deleted": False}


@app.get("/api/ports/current")
async def get_current_ports() -> Dict[str, Any]:
    """Retourne le dernier snapshot des ports et du score de risque.

    Ne déclenche pas de scan à la demande : on lit simplement la dernière mesure.
    """

    async with _snapshot_lock:
        if _snapshot is None:
            # Retour neutre en attendant le premier scan
            return {
                "timestamp": None,
                "risk_score": 0,
                "ports": [],
            }

        return _snapshot


@app.get("/api/export/ports")
async def export_ports(format: str = "json") -> Response:
    """Exporte le snapshot courant des ports en CSV ou JSON."""
    fmt = (format or "json").lower()
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="Format non supporté. Valeurs autorisées : csv, json")

    async with _snapshot_lock:
        if _snapshot is None:
            snapshot = {
                "timestamp": None,
                "risk_score": 0,
                "ports": [],
            }
        else:
            snapshot = _snapshot

    if fmt == "json":
        return Response(
            content=json.dumps(snapshot, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="ports.json"'},
        )

    # Export CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "port",
        "protocol",
        "local_ip",
        "state",
        "pid",
        "process",
        "process_exe",
        "process_cmdline",
        "firewall_blocked",
        "risk",
    ])
    for p in snapshot.get("ports", []):
        proc = p.get("process")
        if isinstance(proc, dict):
            proc_name = proc.get("name", "")
            proc_exe = proc.get("exe", "")
            cmdline = proc.get("cmdline", "")
            proc_cmdline = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline or "")
        else:
            proc_name = str(proc or "")
            proc_exe = ""
            proc_cmdline = ""

        writer.writerow([
            p.get("port", ""),
            p.get("protocol", ""),
            p.get("local_ip", ""),
            p.get("state", ""),
            p.get("pid", ""),
            proc_name,
            proc_exe,
            proc_cmdline,
            p.get("firewall_blocked", ""),
            p.get("risk", ""),
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ports.csv"'},
    )


@app.get("/api/export/alerts")
async def export_alerts(format: str = "json", limit: int = 500) -> Response:
    """Exporte l'historique des alertes en CSV ou JSON via HistoryManager."""
    fmt = (format or "json").lower()
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="Format non supporté. Valeurs autorisées : csv, json")

    try:
        history = HistoryManager()
        alerts = history.get_alerts(limit=limit)
    except Exception as e:
        print(f"Erreur export_alerts: {e}")
        alerts = []

    if fmt == "json":
        return Response(
            content=json.dumps(alerts, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="alerts.json"'},
        )

    # Export CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "risk_score", "message"])
    for alert in alerts:
        writer.writerow([
            alert.get("id", ""),
            alert.get("timestamp", ""),
            alert.get("risk_score", ""),
            alert.get("message", ""),
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="alerts.csv"'},
    )


@app.get("/api/inspect/process/{pid}")
async def inspect_process(pid: int) -> JSONResponse:
    """Inspecte un processus : chemin réel, empreinte SHA-256, réputation MalwareBazaar et liens utiles."""
    if inspect_process_by_pid is None:
        raise HTTPException(status_code=503, detail="Module de réputation indisponible")

    try:
        data = await inspect_process_by_pid(pid)
    except (ProcessLookupError, psutil.NoSuchProcess):
        raise HTTPException(status_code=404, detail=f"Processus PID {pid} inexistant")
    except Exception as e:
        print(f"Erreur inspection processus {pid}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Si réputation malveillante : ajouter une alerte critique à l'historique
    if data.get("reputation") == "malicious":
        try:
            sig = data.get("signature") or "Inconnu"
            proc_name = data.get("process_name") or f"PID_{pid}"
            history = HistoryManager()
            _record_alert(
                history, 90,
                f"Malware detecte : {sig} ({proc_name} PID {pid})"
            )
        except Exception as e:
            print(f"Erreur enregistrement alerte réputation: {e}")

    return JSONResponse(content=data)



@app.post("/api/hardening/plan")
async def create_hardening_plan(request: HardeningPlanRequest) -> Dict[str, Any]:
    """Génère un plan de durcissement à partir des ports sélectionnés.

    Écrit un fichier JSON dans le répertoire du dashboard et renvoie :
    - le chemin du fichier de plan
    - une commande PowerShell suggérée pour l'utiliser avec le script de hardening.
    """

    # Normalisation minimale des données
    ports_payload = [
        {
            "port": p.port,
            "protocol": p.protocol.lower(),
            "risk": (p.risk or "").lower(),
        }
        for p in request.ports
    ]

    plan = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "action": (request.action or "harden").lower(),
        "ports": ports_payload,
    }

    plan_path = paths.plans_dir() / "hardening_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # Commandes PowerShell suggérées — chemins absolus : en mode installé le
    # plan vit sous %LOCALAPPDATA% et les scripts dans {app}\scripts.
    script = paths.scripts_dir() / "powershell" / "security_hardening.ps1"
    ps_dry_run = f'& "{script}" -Plan "{plan_path}" -DryRun'
    ps_apply = f'& "{script}" -Plan "{plan_path}"'

    return {
        "plan_file": str(plan_path),
        "powershell_dry_run": ps_dry_run,
        "powershell_apply": ps_apply,
        "ports_count": len(ports_payload),
    }


@app.post("/api/audit/generate-plan")
async def generate_audit_hardening_plan() -> Dict[str, Any]:
    """Génère un plan de durcissement à partir des ports exposés non protégés de audit_data.json.

    Écrit web_port_dashboard/hardening_plan.json et retourne {success, plan_path, ports_count}.
    """
    base_dir = paths.plans_dir()
    audit_file = paths.writable_root() / "audit_data.json"
    audit_data = None

    if audit_file.is_file():
        try:
            with audit_file.open("r", encoding="utf-8") as f:
                audit_data = json.load(f)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la lecture de audit_data.json : {e}"
            )
    else:
        fallback = Path("audit_data.json")
        if fallback.is_file():
            try:
                with fallback.open("r", encoding="utf-8") as f:
                    audit_data = json.load(f)
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de la lecture de audit_data.json : {e}"
                )
        else:
            # Depuis l'application installée, audit_data.json n'est pas un
            # artefact obligatoire : le scan périodique possède déjà les mêmes
            # ports dans _snapshot. Matérialiser ce snapshot pour permettre
            # l'application directe des recommandations.
            if _snapshot is None:
                raise HTTPException(
                    status_code=503,
                    detail="Aucun scan réseau disponible pour générer le plan"
                )
            audit_data = {
                "exposed_ports_detail": [
                    port for port in _snapshot.get("ports", [])
                    if port.get("local_ip") in {"0.0.0.0", "*", "::"}
                    and not port.get("firewall_blocked", False)
                ]
            }

    exposed_ports = audit_data.get("exposed_ports_detail", [])
    ports_payload = []

    for item in exposed_ports:
        # Ports exposés non protégés par le pare-feu
        if not item.get("firewall_blocked", False):
            try:
                port_num = int(item["port"])
            except (KeyError, ValueError, TypeError):
                continue

            protocol = str(item.get("protocol", "tcp")).lower()
            risk = str(item.get("risk") or item.get("risk_level") or "unexpected").lower()

            ports_payload.append({
                "port": port_num,
                "protocol": protocol,
                "risk": risk,
            })

    plan = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "action": "harden",
        "source": "audit_data.json",
        "ports": ports_payload,
    }

    plan_path = base_dir / "hardening_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # Chemins absolus : en mode installé le plan vit sous %LOCALAPPDATA% et
    # les scripts dans {app}\scripts — relative_to() échouerait (ValueError).
    script = paths.scripts_dir() / "powershell" / "security_hardening.ps1"
    ps_dry_run = f'& "{script}" -Plan "{plan_path}" -DryRun'
    ps_apply = f'& "{script}" -Plan "{plan_path}"'

    return {
        "success": True,
        "plan_path": str(plan_path),
        "ports_count": len(ports_payload),
        "plan_file": str(plan_path),
        "powershell_dry_run": ps_dry_run,
        "powershell_apply": ps_apply,
    }


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    """Page HTML principale du dashboard.

    Sert le fichier static/index.html. Si le fichier est introuvable,
    renvoie un message minimal pour éviter un 404.
    """

    index_path = paths.module_dir() / "static" / "index.html"
    try:
        return index_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<html><body><h1>Cerbere Security Shield</h1><p>Fichier static/index.html introuvable.</p></body></html>"


# ============= ENDPOINTS DETECTION D'INTRUSION =============

@app.get("/api/intrusion/dashboard")
async def get_intrusion_dashboard() -> Dict[str, Any]:
    """Retourne les données du tableau de bord de détection d'intrusion."""
    detector = _require_detector()
    return detector.get_dashboard_data()


@app.get("/api/intrusion/events")
async def get_intrusion_events(hours: int = 6, limit: int = 50) -> List[Dict[str, Any]]:
    """Retourne les événements de sécurité récents."""
    detector = _require_detector()
    data = detector.get_dashboard_data()
    return data.get('recent_events', [])[:limit]


@app.get("/api/intrusion/banned")
async def get_banned_ips(limit: int = 50) -> List[Dict[str, Any]]:
    """Retourne la liste des IP bannies."""
    detector = _require_detector()
    return detector.get_banned_ips(limit=limit)


class UnbanRequest(BaseModel):
    """Payload pour débannir une IP."""
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", description="Adresse IPv4 valide")


@app.post("/api/intrusion/unban")
async def unban_ip(request: UnbanRequest) -> Dict[str, Any]:
    """Débannit manuellement une IP."""
    detector = _require_detector()
    success = detector.unban_ip(request.ip)
    if success:
        return {"success": True, "message": f"IP {request.ip} débannie"}
    else:
        return {"success": False, "message": f"Impossible de débannir l'IP {request.ip}"}


class WhitelistRequest(BaseModel):
    """Payload pour gérer la whitelist."""
    action: str = Field(..., pattern="^(add|remove)$")
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", description="Adresse IPv4 valide")


@app.post("/api/intrusion/whitelist")
async def manage_whitelist(request: WhitelistRequest) -> Dict[str, Any]:
    """Gère la whitelist (ajout/retrait)."""
    detector = _require_detector()
    
    if request.action == "add":
        success = detector.add_to_whitelist(request.ip)
        if success:
            return {"success": True, "message": f"IP {request.ip} ajoutée à la whitelist"}
    elif request.action == "remove":
        success = detector.remove_from_whitelist(request.ip)
        if success:
            return {"success": True, "message": f"IP {request.ip} retirée de la whitelist"}
    
    return {"success": False, "message": "Action invalide"}


@app.get("/api/intrusion/whitelist")
async def get_whitelist() -> Dict[str, Any]:
    """Retourne la whitelist actuelle."""
    detector = _require_detector()
    return {"whitelist": detector.get_whitelist()}


@app.post("/api/intrusion/start")
async def start_intrusion_detection() -> Dict[str, Any]:
    """Démarre la surveillance de détection d'intrusion."""
    detector = _require_detector()
    if not detector.running:
        detector.start_monitoring()
        return {"success": True, "message": "Surveillance de détection d'intrusion démarrée"}
    else:
        return {"success": True, "message": "Surveillance déjà en cours"}


@app.post("/api/intrusion/test")
async def test_intrusion_detection() -> Dict[str, Any]:
    """Simuler une attaque pour tester la détection"""
    detector = _require_detector()
    if detector:
        try:
            # Créer un événement de test sans importer SecurityEvent
            from datetime import datetime
            
            # Construire un vrai SecurityEvent pour le détecteur
            from intrusion_detector import SecurityEvent
            test_event = SecurityEvent(
                timestamp=datetime.now(),
                event_type="FAILED_LOGIN",
                source_ip="192.0.2.1",  # IP de test (TEST-NET-1)
                target_service="ssh",
                details="Test event - failed login attempt",
                severity="HIGH"
            )
            
            # Traiter l'événement
            detector.detect_intrusions([test_event])
            
            return {"success": True, "message": "Événement de test injecté"}
        except Exception as e:
            print(f"Erreur lors du test: {e}")
            return {"success": False, "message": f"Erreur: {str(e)}"}
    return {"success": False, "message": "Détecteur non disponible"}

@app.post("/api/intrusion/stop")
async def stop_intrusion_detection() -> Dict[str, Any]:
    """Arrête la surveillance de détection d'intrusion."""
    detector = _require_detector()
    if detector.running:
        detector.stop_monitoring()
        return {"success": True, "message": "Surveillance de détection d'intrusion arrêtée"}
    else:
        return {"success": True, "message": "Surveillance déjà arrêtée"}


@app.get("/api/intrusion/status")
async def get_intrusion_status() -> Dict[str, Any]:
    """Retourne le statut de la détection d'intrusion."""
    detector = _require_detector()
    return {
        "running": detector.running,
        "active_bans": len(detector.banned_ips),
        "whitelist_size": len(detector.whitelist)
    }


# ============= FIN ENDPOINTS DETECTION D'INTRUSION =============


# ============= ENDPOINTS FILTRAGE DNS & TRACKERS =============

@app.get("/api/filter/status")
async def get_filter_status() -> Dict[str, Any]:
    """Retourne le statut actuel du filtrage DNS et des trackers."""
    global _sinkhole
    try:
        f_state = _load_filter_state()
        enabled = bool(f_state.get("enabled", False))
        running = bool(_sinkhole and getattr(_sinkhole, "running", False))
        domains_count = len(getattr(_sinkhole, "domaines", [])) if _sinkhole else 0
        stats = getattr(_sinkhole, "stats", {}) if _sinkhole else {}
        queries_total = stats.get("queries_total", 0)
        blocked_total = stats.get("blocked_total", 0)
        if _sinkhole and hasattr(_sinkhole, "whitelist"):
            whitelist_count = len(_sinkhole.whitelist)
        else:
            whitelist_count = len(_get_effective_whitelist())

        initialization_error = (
            getattr(_sinkhole, "initialization_error", None) if _sinkhole else None
        )
        return {
            "enabled": enabled and running,
            "running": running,
            "domains_count": domains_count,
            "queries_total": queries_total,
            "blocked_total": blocked_total,
            "whitelist_count": whitelist_count,
            "error": initialization_error,
        }
    except Exception as e:
        print(f"Erreur get_filter_status: {e}")
        return {
            "enabled": False,
            "running": False,
            "domains_count": 0,
            "queries_total": 0,
            "blocked_total": 0,
            "whitelist_count": 0,
        }


@app.post("/api/filter/start")
async def start_filter() -> Dict[str, Any]:
    """Démarre le filtrage DNS et met à jour l'état persistant."""
    global _sinkhole
    try:
        if DnsSinkhole is None or (load_domain_set is None and load_domain_map is None):
            return {
                "success": False,
                "enabled": False,
                "running": False,
                "message": "Module tracker_filter ou pydivert indisponible",
            }

        state_dir = paths.state_dir()
        if _sinkhole is None or not _sinkhole.running:
            domaines, domain_meta = await asyncio.to_thread(
                _load_combined_domain_map, str(state_dir)
            )
            whitelist = _get_effective_whitelist(str(state_dir))
            history = HistoryManager()
            _sinkhole = DnsSinkhole(
                domaines=domaines,
                whitelist=whitelist,
                alert_callback=lambda s, m: _record_alert(history, s, m),
                domain_meta=domain_meta,
                notify_grace_seconds=float(_runtime_cfg().get("notify_grace_seconds", 60)),
                state_dir=str(state_dir),
                rule_resolver=(
                    _get_rules_engine().decide if _get_rules_engine() is not None else None
                ),
            )

        if not _sinkhole.running:
            _sinkhole.start()
            await asyncio.sleep(0.15)

        running = bool(getattr(_sinkhole, "running", False))
        if not running:
            error = getattr(_sinkhole, "initialization_error", None)
            _save_filter_state({"enabled": False})
            _sync_protection_state(False)
            return {
                "success": False,
                "enabled": False,
                "running": False,
                "error": error,
                "message": "Impossible de démarrer le filtrage DNS : privilèges administrateur requis",
            }

        _save_filter_state({"enabled": True})
        _sync_protection_state(True)
        logger.info("Filtrage DNS démarré (%d domaines en liste)", len(getattr(_sinkhole, "domaines", [])))
        return {
            "success": True,
            "enabled": True,
            "running": True,
            "message": "Filtrage trackers démarré",
        }
    except (ImportError, Exception) as e:
        print(f"Erreur start_filter: {e}")
        return {
            "success": False,
            "enabled": False,
            "running": False,
            "message": f"Erreur démarrage filtrage : {e}",
        }


@app.post("/api/filter/stop")
async def stop_filter() -> Dict[str, Any]:
    """Arrête le filtrage DNS et met à jour l'état persistant."""
    global _sinkhole
    try:
        if _sinkhole is not None:
            if getattr(_sinkhole, "running", False):
                _sinkhole.stop()
            _sinkhole = None
        _save_filter_state({"enabled": False})
        _sync_protection_state(False)
        logger.info("Filtrage DNS arrêté")
        return {
            "success": True,
            "enabled": False,
            "running": False,
            "message": "Filtrage trackers arrêté",
        }
    except Exception as e:
        print(f"Erreur stop_filter: {e}")
        return {
            "success": False,
            "enabled": False,
            "running": False,
            "message": f"Erreur arrêt filtrage : {e}",
        }


@app.get("/api/filter/stats")
async def get_filter_stats() -> Dict[str, Any]:
    """Retourne les compteurs et le top 15 des domaines bloqués."""
    global _sinkhole
    try:
        if _sinkhole is not None and hasattr(_sinkhole, "stats"):
            stats = _sinkhole.stats
            blocked_domains = stats.get("blocked_domains")
            if hasattr(blocked_domains, "most_common"):
                top_domains = blocked_domains.most_common(15)
            else:
                top_domains = []
            return {
                "blocked_total": stats.get("blocked_total", 0),
                "queries_total": stats.get("queries_total", 0),
                "top_domains": top_domains,
            }
        return {
            "blocked_total": 0,
            "queries_total": 0,
            "top_domains": [],
        }
    except Exception as e:
        print(f"Erreur get_filter_stats: {e}")
        return {
            "blocked_total": 0,
            "queries_total": 0,
            "top_domains": [],
        }


@app.get("/api/filter/blocked")
async def get_filter_blocked() -> List[Dict[str, Any]]:
    """Retourne la liste complète des domaines bloqués avec métadonnées, triée par count desc."""
    global _sinkhole
    try:
        if _sinkhole is not None and hasattr(_sinkhole, "stats"):
            stats = _sinkhole.stats
            # Whitelist effective pour marquer les domaines deja autorises
            try:
                wl_now = _get_effective_whitelist()
            except Exception:
                wl_now = set()

            def _is_whitelisted(dom: str) -> bool:
                parts = dom.split(".")
                cands = [".".join(parts[i:]) for i in range(len(parts) - 1)] or [dom]
                return any(c in wl_now for c in cands)

            blocked_detail = stats.get("blocked_detail")
            if isinstance(blocked_detail, dict) and blocked_detail:
                items = []
                for dom, d in blocked_detail.items():
                    items.append({
                        "domain": dom,
                        "count": d.get("count", 0),
                        "matched_domain": d.get("matched_domain", dom),
                        "sources": list(d.get("sources", [])),
                        "rule": d.get("rule", ""),
                        "first_seen": d.get("first_seen"),
                        "last_seen": d.get("last_seen"),
                        "whitelisted": _is_whitelisted(dom),
                    })
                items.sort(key=lambda x: x["count"], reverse=True)
                return items

            # Fallback sur Counter si blocked_detail absent ou vide
            blocked_domains = stats.get("blocked_domains")
            if blocked_domains:
                items = []
                for dom, count in blocked_domains.items():
                    items.append({
                        "domain": dom,
                        "count": count,
                        "matched_domain": dom,
                        "sources": [],
                        "rule": "",
                        "whitelisted": _is_whitelisted(dom),
                    })
                items.sort(key=lambda x: x["count"], reverse=True)
                return items

        return []
    except Exception as e:
        print(f"Erreur get_filter_blocked: {e}")
        return []


@app.get("/api/filter/whitelist")
async def get_filter_whitelist() -> Dict[str, List[str]]:
    """Retourne la configuration des domaines en whitelist : defaults, custom et disabled_defaults."""
    try:
        defaults = sorted(list(_get_default_whitelist()))
        cfg = _load_filter_whitelist_config()
        return {
            "defaults": defaults,
            "custom": cfg.get("custom", []),
            "disabled_defaults": cfg.get("disabled_defaults", []),
        }
    except Exception as e:
        print(f"Erreur get_filter_whitelist: {e}")
        return {
            "defaults": [],
            "custom": [],
            "disabled_defaults": [],
        }


@app.post("/api/filter/whitelist/reset")
async def reset_filter_whitelist() -> Dict[str, Any]:
    """Réinitialise la whitelist : vide custom + disabled_defaults.

    Après reset, la whitelist effective redevient exactement la liste
    par défaut embarquée (tracker_filter/data/default_whitelist.txt).
    """
    global _sinkhole
    try:
        _save_filter_whitelist_config([], [])
        effective = _get_effective_whitelist(str(_state_dir()))
        if _sinkhole is not None and hasattr(_sinkhole, "whitelist"):
            _sinkhole.whitelist = set(effective)
        logger.info("Whitelist filtrage réinitialisée aux valeurs par défaut")
        return {
            "success": True,
            "whitelist_count": len(effective),
            "message": "Whitelist réinitialisée aux domaines par défaut",
        }
    except Exception as e:
        return {"success": False, "message": f"Erreur réinitialisation : {e}"}


@app.post("/api/filter/whitelist")
async def modify_filter_whitelist(payload: FilterWhitelistRequest) -> Dict[str, Any]:
    """Ajoute ou retire un domaine de la whitelist (gestion defaults, custom, disabled_defaults)."""
    global _sinkhole
    try:
        domain = payload.domain.strip().lower()
        if not domain:
            return {"success": False, "message": "Domaine vide"}

        defaults_set = _get_default_whitelist()
        cfg = _load_filter_whitelist_config()
        custom_set = set(cfg.get("custom", []))
        disabled_set = set(cfg.get("disabled_defaults", []))

        if payload.action == "add":
            # Si le domaine était un default désactivé -> le réhabiliter
            if domain in disabled_set:
                disabled_set.discard(domain)
            # S'il n'est pas un domaine par défaut, l'ajouter à custom
            if domain not in defaults_set:
                custom_set.add(domain)
        elif payload.action == "remove":
            # Si le domaine fait partie des defaults -> l'ajouter à disabled_defaults
            if domain in defaults_set:
                disabled_set.add(domain)
            # Dans tous les cas, le retirer de custom s'il y figurait
            custom_set.discard(domain)

        custom_list = sorted(list(custom_set))
        disabled_list = sorted(list(disabled_set))
        _save_filter_whitelist_config(custom_list, disabled_list)
        logger.info("Whitelist filtrage : %s %s", payload.action, domain)

        # Calcul de la whitelist effective : defaults ∪ user − disabled_defaults
        effective_wl = (defaults_set | custom_set) - disabled_set

        # Mettre à jour l'ensemble effectif dans le sinkhole actif
        if _sinkhole is not None and hasattr(_sinkhole, "whitelist"):
            _sinkhole.whitelist = set(effective_wl)

        return {
            "success": True,
            "action": payload.action,
            "domain": domain,
            "whitelist": sorted(list(effective_wl)),
            "defaults": sorted(list(defaults_set)),
            "custom": custom_list,
            "disabled_defaults": disabled_list,
        }
    except Exception as e:
        print(f"Erreur modify_filter_whitelist: {e}")
        return {"success": False, "message": str(e)}


@app.get("/api/filter/inspect/{domain}")
async def inspect_blocked_domain(domain: str) -> Dict[str, Any]:
    """Enrichit un domaine bloqué : règle locale + RDAP + URLhaus + DoH.

    Lecture seule, sans effet de bord. Chaque source externe est fail-open :
    en cas d'indisponibilité, la sous-section correspondante est simplement
    marquée indisponible."""
    import re as _re
    domain = domain.strip().lower()
    if not domain or len(domain) > 253 or not _re.fullmatch(r"[a-z0-9._-]+", domain):
        raise HTTPException(status_code=400, detail="Domaine invalide")

    # Infos locales du sinkhole actif (règle, sources, compteur, timestamps)
    local_detail = {}
    if _sinkhole is not None:
        detail = getattr(_sinkhole, "stats", {}).get("blocked_detail", {}).get(domain)
        if detail:
            local_detail = dict(detail)

    if inspect_domain is None:
        return {"domain": domain, "local": local_detail,
                "links": {}, "rdap": {}, "urlhaus": {}, "dns": {},
                "error": "module domain_intel indisponible"}

    # Appels réseau bloquants -> thread séparé pour ne pas geler l'event loop
    return await asyncio.to_thread(inspect_domain, domain, local_detail)

# ============= FIN ENDPOINTS FILTRAGE DNS & TRACKERS =============


# Point d'entrée CLI pratique : `python -m web_port_dashboard.port_dashboard`
# ============= CONTRÔLE PARENTAL / DOMESTIQUE (T52) =============

class PinSetRequest(BaseModel):
    old_pin: str = Field(default="")
    new_pin: str = Field(default="")


class PinVerifyRequest(BaseModel):
    pin: str = Field(default="")


class ScopeToggleRequest(BaseModel):
    enabled: bool


class ScopeRulesRequest(BaseModel):
    categories: Dict[str, Any] = Field(default_factory=dict)
    domains: Dict[str, Any] = Field(default_factory=dict)


class CookiesPurgeRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)


def _scope_rules(engine, scope: str) -> Dict[str, Any]:
    rules = engine.get_rules()
    return rules.get(scope, {"enabled": False, "categories": {}, "domains": {}})


def _blocked_journal(scope: str) -> List[Dict[str, Any]]:
    """Blocages du sinkhole filtrés par scope ('' = filtre tracker)."""
    if _sinkhole is None:
        return []
    detail = getattr(_sinkhole, "stats", {}).get("blocked_detail", {}) or {}
    return [
        {"domain": d, **info}
        for d, info in detail.items()
        if info.get("scope", "") == scope
    ]


@app.get("/api/parental/status")
async def parental_status() -> Dict[str, Any]:
    pin = _get_pin_manager()
    engine = _get_rules_engine()
    rules = _scope_rules(engine, "parental") if engine else {}
    return {
        "available": engine is not None and pin is not None,
        "enabled": bool(rules.get("enabled")),
        "pin_set": pin.is_set() if pin else False,
        "categories": rules.get("categories", {}),
        "domains": rules.get("domains", {}),
        "quotas": engine.quota_status() if engine else {},
        "lists": _lists_manager.list_categories() if _lists_manager else {},
    }


@app.post("/api/parental/pin")
async def parental_set_pin(req: PinSetRequest) -> Dict[str, Any]:
    """Définit le PIN initial ou le change (ancien PIN requis si déjà défini)."""
    pin = _get_pin_manager()
    if pin is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    try:
        if pin.is_set():
            if not pin.change_pin(req.old_pin, req.new_pin):
                raise HTTPException(
                    status_code=403,
                    detail="Ancien PIN incorrect, format invalide ou verrouillage actif.",
                )
        else:
            pin.set_pin(req.new_pin)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True}


@app.post("/api/parental/verify")
async def parental_verify(req: PinVerifyRequest, response: Response) -> Dict[str, Any]:
    """Vérifie le PIN et ouvre une session parentale courte (cookie, 10 min)."""
    pin = _get_pin_manager()
    if pin is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    wait = pin.remaining_lockout_seconds()
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Verrouillé. Réessayez dans {wait} s.")
    if not pin.verify(req.pin):
        wait = pin.remaining_lockout_seconds()
        detail = "PIN incorrect."
        if wait > 0:
            detail = f"Trop d'échecs — verrouillé {wait} s."
        raise HTTPException(status_code=401, detail=detail)
    token = secrets.token_urlsafe(32)
    _parental_sessions[token] = time.time() + _PARENTAL_SESSION_SECONDS
    response.set_cookie("cerbere_parental", token, httponly=True, samesite="lax")
    return {"success": True}


@app.post("/api/parental/toggle")
async def parental_toggle(req: ScopeToggleRequest, request: Request) -> Dict[str, Any]:
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    engine.set_scope_enabled("parental", req.enabled)
    if req.enabled and _lists_manager is not None:
        # Télécharge les listes de catégories en tâche de fond (fail-open).
        asyncio.get_event_loop().run_in_executor(None, _lists_manager.refresh)
    logger.info("Contrôle parental %s", "activé" if req.enabled else "désactivé")
    return {"success": True, "enabled": req.enabled}


@app.get("/api/parental/rules")
async def parental_get_rules() -> Dict[str, Any]:
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    return _scope_rules(engine, "parental")


@app.put("/api/parental/rules")
async def parental_put_rules(req: ScopeRulesRequest, request: Request) -> Dict[str, Any]:
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    try:
        engine.update_scope("parental", req.categories, req.domains)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True}


@app.post("/api/parental/reset")
async def parental_reset(request: Request) -> Dict[str, Any]:
    """Remet à zéro le contrôle parental : règles vidées + protection OFF."""
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    engine.update_scope("parental", {}, {})
    engine.set_scope_enabled("parental", False)
    logger.info("Contrôle parental réinitialisé (règles vidées, désactivé)")
    return {"success": True, "enabled": False}


@app.get("/api/parental/blocked")
async def parental_blocked() -> Dict[str, Any]:
    return {"items": _blocked_journal("parental")}


@app.get("/api/domestic/status")
async def domestic_status() -> Dict[str, Any]:
    engine = _get_rules_engine()
    rules = _scope_rules(engine, "domestic") if engine else {}
    return {
        "available": engine is not None,
        "enabled": bool(rules.get("enabled")),
        "categories": rules.get("categories", {}),
        "domains": rules.get("domains", {}),
        "lists": _lists_manager.list_categories() if _lists_manager else {},
        "cookies_available": CookieScanner is not None,
    }


@app.post("/api/domestic/toggle")
async def domestic_toggle(req: ScopeToggleRequest, request: Request) -> Dict[str, Any]:
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    engine.set_scope_enabled("domestic", req.enabled)
    logger.info("Contrôle domestique %s", "activé" if req.enabled else "désactivé")
    return {"success": True, "enabled": req.enabled}


@app.get("/api/domestic/rules")
async def domestic_get_rules() -> Dict[str, Any]:
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    return _scope_rules(engine, "domestic")


@app.put("/api/domestic/rules")
async def domestic_put_rules(req: ScopeRulesRequest, request: Request) -> Dict[str, Any]:
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    try:
        engine.update_scope("domestic", req.categories, req.domains)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True}


@app.post("/api/domestic/reset")
async def domestic_reset(request: Request) -> Dict[str, Any]:
    """Remet à zéro le contrôle domestique : règles vidées + verrou OFF."""
    _require_pin(request)
    engine = _get_rules_engine()
    if engine is None:
        raise HTTPException(status_code=501, detail="Module parental_control indisponible.")
    engine.update_scope("domestic", {}, {})
    engine.set_scope_enabled("domestic", False)
    logger.info("Contrôle domestique réinitialisé (règles vidées, désactivé)")
    return {"success": True, "enabled": False}


@app.get("/api/domestic/blocked")
async def domestic_blocked() -> Dict[str, Any]:
    return {"items": _blocked_journal("domestic")}


@app.post("/api/domestic/cookies/scan")
async def domestic_cookies_scan() -> Dict[str, Any]:
    """Audit des cookies navigateurs : match host_key vs listes de blocage."""
    scanner = _get_cookie_scanner()
    if scanner is None:
        raise HTTPException(status_code=501, detail="Scanner de cookies indisponible.")
    suspect = set()
    if _lists_manager is not None:
        try:
            suspect = set(_lists_manager.get_all_domains(
                list((_lists_manager.list_categories() or {}).keys())
            ))
        except Exception as e:
            logger.debug("Listes indisponibles pour le scan cookies: %s", e)
    findings = await asyncio.to_thread(scanner.scan, suspect)
    return {"findings": [f.__dict__ if hasattr(f, "__dict__") else f for f in findings]}


@app.post("/api/domestic/cookies/purge")
async def domestic_cookies_purge(req: CookiesPurgeRequest, request: Request) -> Dict[str, Any]:
    _require_pin(request)
    scanner = _get_cookie_scanner()
    if scanner is None:
        raise HTTPException(status_code=501, detail="Scanner de cookies indisponible.")
    # Reconvertit les dicts du frontend en Finding (ou tuple browser/host_key).
    from parental_control.cookies_scanner import Finding
    items = []
    for f in req.findings:
        if isinstance(f, dict) and f.get("browser") and f.get("host_key"):
            try:
                items.append(Finding(
                    browser=f["browser"],
                    profile=f.get("profile", ""),
                    host_key=f["host_key"],
                    cookie_name=f.get("cookie_name", ""),
                    matched_domain=f.get("matched_domain", ""),
                ))
            except TypeError:
                items.append((f["browser"], f["host_key"]))
    report = await asyncio.to_thread(scanner.purge, items)
    return {"success": True, "report": report}


# ================= Bloqueur de pub — multi-listes (T62) =================

class AdblockListToggleRequest(BaseModel):
    list_id: str
    enabled: bool


class AdblockListUpdateRequest(BaseModel):
    list_id: Optional[str] = None


class SchedulerConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    interval_hours: Optional[float] = None


@app.get("/api/adblock/lists")
async def adblock_lists() -> Dict[str, Any]:
    """Registre des listes de blocage pub + état (activée, domaines, MAJ)."""
    mgr = _get_adblock_manager()
    if mgr is None:
        return {"available": False, "lists": {}}
    return {"available": True, "lists": mgr.status()}


@app.post("/api/adblock/lists")
async def adblock_toggle_list(req: AdblockListToggleRequest) -> Dict[str, Any]:
    """Active/désactive une liste de blocage pub — appliqué à chaud au sinkhole."""
    mgr = _get_adblock_manager()
    if mgr is None:
        raise HTTPException(status_code=501, detail="Module adblock indisponible.")
    try:
        status = await asyncio.to_thread(mgr.set_enabled, req.list_id, req.enabled)
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    count = await asyncio.to_thread(_rebuild_sinkhole_domains)
    logger.info("Liste adblock %s -> %s (%d domaines actifs)", req.list_id, req.enabled, count)
    return {"success": True, "lists": status, "blocked_domains": count}


@app.post("/api/adblock/lists/update")
async def adblock_update_list(req: AdblockListUpdateRequest) -> Dict[str, Any]:
    """Force le téléchargement d'une liste (ou de toutes si list_id absent)."""
    mgr = _get_adblock_manager()
    if mgr is None:
        raise HTTPException(status_code=501, detail="Module adblock indisponible.")
    report = await asyncio.to_thread(mgr.refresh, req.list_id)
    count = await asyncio.to_thread(_rebuild_sinkhole_domains)
    return {"success": True, "report": report, "blocked_domains": count}


@app.get("/api/adblock/stats")
async def adblock_stats() -> Dict[str, Any]:
    """Statistiques agrégées du bloqueur de pub."""
    mgr = _get_adblock_manager()
    lists = mgr.status() if mgr is not None else {}
    enabled = [lid for lid, s in lists.items() if s.get("enabled")]
    return {
        "available": mgr is not None,
        "running": bool(_sinkhole and getattr(_sinkhole, "running", False)),
        "enabled_lists": enabled,
        "blocked_domains": len(getattr(_sinkhole, "domaines", [])) if _sinkhole else 0,
        "blocked_total": getattr(_sinkhole, "stats", {}).get("blocked_total", 0) if _sinkhole else 0,
        "scheduler": {
            "running": bool(_list_scheduler and getattr(_list_scheduler, "is_running", False)),
            "last_run": getattr(_list_scheduler, "last_run_report", None) if _list_scheduler else None,
        },
    }


@app.get("/api/lists/status")
async def all_lists_status() -> Dict[str, Any]:
    """État de TOUTES les listes téléchargées : adblock + catégories parentales."""
    mgr = _get_adblock_manager()
    adblock = mgr.status() if mgr is not None else {}
    parental = {}
    engine = _get_rules_engine()
    if _lists_manager is not None:
        try:
            parental = _lists_manager.list_categories()
        except Exception:
            parental = {}
    elif engine is not None:
        pass
    return {"adblock": adblock, "parental": parental}


@app.post("/api/lists/update_all")
async def lists_update_all() -> Dict[str, Any]:
    """Met à jour toutes les listes téléchargées (adblock + catégories parentales)."""
    if update_all_lists is None:
        raise HTTPException(status_code=501, detail="Gestionnaire de mises à jour indisponible.")
    report = await asyncio.to_thread(update_all_lists, str(_state_dir()))
    count = await asyncio.to_thread(_rebuild_sinkhole_domains)
    return {"success": True, "report": report, "blocked_domains": count}


def _scheduler_config_file() -> Path:
    return _state_dir() / "update_scheduler.json"


@app.get("/api/lists/scheduler_config")
async def get_scheduler_config() -> Dict[str, Any]:
    """Configuration du planificateur de mises à jour des listes."""
    cfg = {}
    try:
        if _scheduler_config_file().is_file():
            cfg = json.loads(_scheduler_config_file().read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "interval_hours": float(cfg.get("interval_hours", 24.0)),
        "running": bool(_list_scheduler and getattr(_list_scheduler, "is_running", False)),
    }


@app.put("/api/lists/scheduler_config")
async def put_scheduler_config(req: SchedulerConfigRequest) -> Dict[str, Any]:
    """Persiste la config du planificateur (appliquée au prochain démarrage,
    ou immédiatement pour le toggle enabled)."""
    global _list_scheduler
    cfg = {}
    try:
        if _scheduler_config_file().is_file():
            cfg = json.loads(_scheduler_config_file().read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    if req.enabled is not None:
        cfg["enabled"] = req.enabled
    if req.interval_hours is not None:
        cfg["interval_hours"] = max(1.0, float(req.interval_hours))
    _scheduler_config_file().write_text(
        json.dumps(cfg, indent=2), encoding="utf-8"
    )
    # Application à chaud du toggle enabled
    if req.enabled is not None and ListUpdateScheduler is not None:
        if req.enabled:
            if _list_scheduler is None:
                _list_scheduler = ListUpdateScheduler(state_dir=str(_state_dir()))
            _list_scheduler.enabled = True
            _list_scheduler.start()
        elif _list_scheduler is not None:
            _list_scheduler.enabled = False
            _list_scheduler.stop()
    logger.info("Config scheduler listes : %s", cfg)
    return {"success": True, "config": cfg}


# Référence au serveur uvicorn pour l'arrêt propre via /api/shutdown
_uvicorn_server = None


@app.post("/api/shutdown")
async def shutdown_app(request: Request) -> Dict[str, Any]:
    """Arrête complètement l'application (backend + surveillance + filtrage).

    Appelé par le systray sur « Quitter ». La réponse est renvoyée avant
    l'arrêt effectif, déclenché dans un thread différé. Les handlers
    shutdown FastAPI (stop sinkhole, detector…) s'exécutent normalement.

    Si le contrôle parental ou domestique est actif, l'arrêt complet exige
    une session PIN valide — sinon l'interface peut se fermer mais le
    backend (sinkhole) continue de protéger la machine."""
    engine = _get_rules_engine()
    protection_active = engine is not None and (
        engine.is_enabled("parental") or engine.is_enabled("domestic")
    )
    if protection_active and not _pin_ok(request):
        # Le systray ne porte pas de cookie : il peut envoyer le PIN en corps.
        pin_ok = False
        pin_mgr = _get_pin_manager()
        try:
            body = await request.json()
            pin_ok = bool(pin_mgr and pin_mgr.verify(str(body.get("pin", ""))))
        except Exception:
            pin_ok = False
        if not pin_ok:
            logger.info("Arrêt complet refusé : protection active, PIN parental requis")
            raise HTTPException(
                status_code=403,
                detail="Protection active : le PIN parental est requis pour arrêter complètement l'application.",
            )
    def _deferred_stop() -> None:
        time.sleep(0.6)
        if _uvicorn_server is not None:
            _uvicorn_server.should_exit = True
        else:
            # Fallback : arrêt dur si le serveur n'est pas la référence attendue
            os._exit(0)

    logger.info("Arrêt complet de l'application demandé via /api/shutdown")
    threading.Thread(target=_deferred_stop, daemon=True).start()
    return {"success": True, "message": "Arrêt de l'application en cours…"}


if __name__ == "__main__":
    import uvicorn

    # Instance conservée pour permettre l'arrêt propre via /api/shutdown
    _uvicorn_server = uvicorn.Server(
        uvicorn.Config(app, host="localhost", port=4050, reload=False)
    )
    _uvicorn_server.run()
