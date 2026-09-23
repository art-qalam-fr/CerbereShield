# tests/test_security.py — Suite de tests PRD T10
import json
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

# Bootstrap sys.path : racine projet + sous-packages
PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DASH_ROOT = PROJECT_ROOT / "web_port_dashboard"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts" / "python"

for p in (PROJECT_ROOT, WEB_DASH_ROOT, SCRIPTS_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from security_audit.collector import NetworkCollector
from web_port_dashboard.risk_evaluator import RiskEvaluator
from intrusion_detector import IntrusionDetector, SecurityEvent
import port_dashboard
from port_dashboard import _require_detector


@pytest.fixture
def collector():
    return NetworkCollector()


def _net_data(port, proc_name, pid=1234, state="LISTENING", proto="tcp"):
    return {
        "timestamp": "2026-09-20T00:00:00",
        "ports": [
            {
                "proto": proto,
                "protocol": proto,
                "local_address": "0.0.0.0",
                "ip": "0.0.0.0",
                "local_ip": "0.0.0.0",
                "port": port,
                "state": state,
                "status": state,
                "pid": pid,
                "process": {"name": proc_name, "pid": pid},
                "process_name": proc_name,
            }
        ],
        "exposed_ports": [],
    }


def test_collector_ports_have_int_pid(collector):
    """Chaque entrée de _scan_ports_psutil a un pid int ou None (jamais str)."""
    ports = collector._scan_ports_psutil()
    assert isinstance(ports, list)
    for entry in ports:
        assert "pid" in entry
        pid = entry["pid"]
        assert pid is None or isinstance(pid, int), f"pid non int/None : {pid!r}"


def test_resolve_system_processes(collector):
    """Les PID réservés sont résolus en noms symboliques."""
    assert collector._resolve_process_info(4)["name"] == "System"
    assert collector._resolve_process_info(0)["name"] == "Idle"
    assert collector._resolve_process_info(None)["name"] == "unknown"


def test_firewall_cache(collector):
    """Le 2e appel utilise le cache ; invalidate_cache() le vide."""
    first = collector._get_firewall_blocked_ports()
    assert collector._firewall_cache is not None
    t = time.time()
    second = collector._get_firewall_blocked_ports()
    elapsed = time.time() - t
    assert first == second
    assert elapsed < 1.0, f"2e appel trop lent ({elapsed:.2f}s) — cache non utilisé"
    collector.invalidate_cache()
    assert collector._firewall_cache is None


def test_risk_evaluator_critical_port_alert():
    """Port critique + binaire suspect → alerte critical."""
    evaluator = RiskEvaluator({"critical_ports": [445]})
    result = evaluator.evaluate(_net_data(445, "nc.exe"))
    alerts = result.get("alerts", [])
    assert alerts, "Aucune alerte générée"
    alert = alerts[0]
    assert alert["type"] == "process_anomaly"
    assert alert["severity"] == "critical"
    assert alert["port"] == 445
    assert alert["process"].lower() == "nc.exe"


def test_risk_evaluator_no_alert_authorized():
    """Port non critique + binaire non suspect → aucune alerte."""
    evaluator = RiskEvaluator({})
    result = evaluator.evaluate(_net_data(8080, "myapp.exe"))
    assert result.get("alerts") == []


def test_risk_evaluator_system_no_alert():
    """Processus System sur port système → aucune alerte."""
    evaluator = RiskEvaluator({})
    result = evaluator.evaluate(_net_data(135, "System", pid=4))
    assert result.get("alerts") == []


def test_risk_evaluator_suspect_binary_noncritical_port():
    """Binaire suspect sur port non critique → alerte warning."""
    evaluator = RiskEvaluator({})
    result = evaluator.evaluate(_net_data(4444, "ncat.exe"))
    alerts = result.get("alerts", [])
    assert alerts and alerts[0]["severity"] == "warning"


def test_intrusion_monitoring_non_blocking():
    """start_monitoring() retourne immédiatement et lance un thread daemon."""
    detector = IntrusionDetector()
    start = time.time()
    detector.start_monitoring()
    elapsed = time.time() - start
    try:
        assert elapsed < 2.0, f"start_monitoring bloquant : {elapsed:.2f}s"
        assert detector.running is True
        thread = getattr(detector, "monitor_thread", None)
        assert thread is not None and thread.is_alive()
    finally:
        detector.stop_monitoring()
    assert detector.running is False


def test_intrusion_events_persist_and_trigger_real_threshold(tmp_path):
    """Le pipeline réel persiste les événements et déclenche le seuil."""
    config_file = tmp_path / "intrusion.json"
    db_file = tmp_path / "intrusion.db"
    config_file.write_text(
        json.dumps({
            "database_path": str(db_file),
            "whitelist": [],
            "failed_login_threshold": 2,
            "ban_duration": 3600,
        }),
        encoding="utf-8",
    )
    detector = IntrusionDetector(config_path=str(config_file))
    now = datetime.now()
    events = [
        SecurityEvent(now, "FAILED_LOGIN_TEST", "192.0.2.1", "SSH-TEST", "test-1", "HIGH"),
        SecurityEvent(now, "FAILED_LOGIN_TEST", "192.0.2.1", "SSH-TEST", "test-2", "HIGH"),
    ]

    class FakeResult:
        returncode = 0
        stdout = "No rules match"

    with patch("subprocess.run", side_effect=[FakeResult(), FakeResult()]):
        detector.detect_intrusions(events)

    assert detector.is_banned("192.0.2.1") is True
    dashboard = detector.get_dashboard_data()
    assert len([e for e in dashboard["recent_events"] if e["source_ip"] == "192.0.2.1"]) == 2
    assert dashboard["active_bans"] == 1


def test_healthcheck_returns_structured_local_report(tmp_path, monkeypatch):
    """Le bouton de santé retourne une matrice PASS/WARN/FAIL structurée."""
    class FakeDetector:
        db_path = str(tmp_path / "intrusion.db")

        def get_dashboard_data(self):
            return {"stats": {"total_events": 3}}

    scripts_dir = tmp_path / "scripts"
    (scripts_dir / "powershell").mkdir(parents=True)
    (scripts_dir / "powershell" / "security_hardening.ps1").write_text("# test", encoding="utf-8")
    state_dir = tmp_path / "state"
    (state_dir / "filter_lists").mkdir(parents=True)
    (state_dir / "filter_lists" / "domains.txt").write_text("example.test\n", encoding="utf-8")
    monkeypatch.setattr(port_dashboard, "get_detector", lambda: FakeDetector())
    monkeypatch.setattr(port_dashboard.paths, "scripts_dir", lambda: scripts_dir)
    monkeypatch.setattr(port_dashboard.paths, "state_dir", lambda: state_dir)

    async def fake_filter_status():
        return {"running": True, "enabled": True, "domains_count": 1}

    monkeypatch.setattr(port_dashboard, "get_filter_status", fake_filter_status)
    result = asyncio.run(port_dashboard.run_healthcheck())
    assert result["success"] is True
    assert result["summary"]["fail"] == 0
    assert {check["id"] for check in result["checks"]} >= {
        "backend.api", "intrusion.database", "dns.filter", "packaging.paths"
    }


def test_require_detector_503():
    """_require_detector lève HTTP 503 si le détecteur est indisponible."""
    with patch.object(port_dashboard, "get_detector", return_value=None):
        with pytest.raises(HTTPException) as excinfo:
            _require_detector()
    assert excinfo.value.status_code == 503


# ---------- T23 : Inspection & réputation (MalwareBazaar) ----------

import asyncio
import os

from web_port_dashboard import reputation as rep


def _fresh_cache(tmp_path, monkeypatch):
    """Cache SQLite isolé dans tmp_path, injecté comme singleton."""
    cache = rep.ReputationCache(tmp_path / "rep.sqlite")
    monkeypatch.setattr(rep, "_cache_singleton", cache)
    return cache


def test_compute_sha256(tmp_path):
    """SHA-256 réel d'un fichier connu ; None si fichier absent ou chemin nul."""
    import hashlib

    f = tmp_path / "hello.bin"
    f.write_bytes(b"hello world")
    assert rep.compute_sha256(str(f)) == hashlib.sha256(b"hello world").hexdigest()
    assert rep.compute_sha256(str(tmp_path / "missing.bin")) is None
    assert rep.compute_sha256(None) is None


def test_reputation_cache_hit_and_ttl(tmp_path):
    """Le cache sert une entrée < 7 jours ; une entrée expirée est un miss."""
    import sqlite3
    from datetime import datetime, timedelta, timezone

    cache = rep.ReputationCache(tmp_path / "rep.sqlite")
    h = "a" * 64
    cache.set(h, "test.exe", "clean", {"signature": None})
    hit = cache.get(h)
    assert hit and hit["reputation"] == "clean" and hit["cached"] is True

    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    with sqlite3.connect(cache.db_path) as conn:
        conn.execute("UPDATE reputation SET checked_at=? WHERE hash_sha256=?", (old, h))
    assert cache.get(h) is None


def test_reputation_error_never_cached(tmp_path):
    """Une entrée 'error' n'est jamais servie depuis le cache (retry ultérieur)."""
    cache = rep.ReputationCache(tmp_path / "rep.sqlite")
    cache.set("b" * 64, "bad.exe", "error", {})
    assert cache.get("b" * 64) is None


def test_check_reputation_mocked_and_cached(tmp_path, monkeypatch):
    """1er appel = réseau mocké ; 2e appel = cache, aucun appel réseau."""
    _fresh_cache(tmp_path, monkeypatch)
    calls = []

    def fake_query(h):
        calls.append(h)
        return {"reputation": "clean", "signature": None, "file_type": "exe", "tags": []}

    monkeypatch.setattr(rep, "query_malwarebazaar_sync", fake_query)
    r1 = asyncio.run(rep.check_reputation("c" * 64, "x.exe"))
    assert r1["reputation"] == "clean" and r1["source"] == "MalwareBazaar"
    r2 = asyncio.run(rep.check_reputation("c" * 64, "x.exe"))
    assert r2["cached"] is True and len(calls) == 1


def test_check_reputation_malicious(tmp_path, monkeypatch):
    """Verdict MalwareBazaar 'ok' -> malicious + signature."""
    _fresh_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rep,
        "query_malwarebazaar_sync",
        lambda h: {"reputation": "malicious", "signature": "TestSig", "file_type": "exe", "tags": ["trojan"]},
    )
    r = asyncio.run(rep.check_reputation("e" * 64, "evil.exe"))
    assert r["reputation"] == "malicious" and r["signature"] == "TestSig"


def test_check_reputation_network_error(tmp_path, monkeypatch):
    """Timeout/injoignable -> reputation 'error', jamais de crash."""
    _fresh_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rep,
        "query_malwarebazaar_sync",
        lambda h: {"reputation": "error", "signature": None, "file_type": None, "tags": [], "error": "timeout_or_unreachable"},
    )
    r = asyncio.run(rep.check_reputation("d" * 64, "y.exe"))
    assert r["reputation"] == "error"


def test_inspect_process_pid_inconnu():
    """PID inexistant -> ProcessLookupError."""
    with pytest.raises(ProcessLookupError):
        asyncio.run(rep.inspect_process_by_pid(99999999))


def test_inspect_own_pid_structure(tmp_path, monkeypatch):
    """Inspection du PID courant : structure JSON complète."""
    _fresh_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rep,
        "query_malwarebazaar_sync",
        lambda h: {"reputation": "clean", "signature": None, "file_type": "exe", "tags": []},
    )
    r = asyncio.run(rep.inspect_process_by_pid(os.getpid()))
    assert r["pid"] == os.getpid()
    assert r["process_name"]
    assert r["sha256"] is None or len(r["sha256"]) == 64
    assert r["links"]["processlibrary"].endswith("/")
    assert r["links"]["virustotal_name"].startswith("https://www.virustotal.com/gui/search/")


def test_endpoint_inspect_404():
    """La route FastAPI renvoie 404 pour un PID inexistant."""
    from port_dashboard import inspect_process

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(inspect_process(99999999))
    assert excinfo.value.status_code == 404


# ---------- T26 : Suppression manuelle d'alertes ----------


def test_history_manager_delete_alert(tmp_path):
    """Vérifie la suppression d'une alerte dans HistoryManager (T26)."""
    from web_port_dashboard.history_manager_simple import HistoryManager

    manager = HistoryManager(base_dir=tmp_path)
    manager.save_alert(50, "Alerte test 1")
    manager.save_alert(80, "Alerte test 2")

    alerts = manager.get_alerts()
    assert len(alerts) == 2

    # Supprimer la première alerte enregistrée
    first_alert = alerts[1]
    deleted = manager.delete_alert(first_alert["timestamp"], first_alert["message"])
    assert deleted is True

    alerts_after = manager.get_alerts()
    assert len(alerts_after) == 1
    assert alerts_after[0]["message"] == "Alerte test 2"

    # Tentative de suppression sur timestamp inexistant -> False
    deleted_missing = manager.delete_alert("1970-01-01T00:00:00", "Alerte inexistante")
    assert deleted_missing is False


def test_endpoint_delete_alert(tmp_path, monkeypatch):
    """TestClient POST /api/alerts/delete avec isolation de state/ (T26)."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    from web_port_dashboard.history_manager_simple import HistoryManager

    # Isoler HistoryManager sur tmp_path pour ne jamais toucher à state/alerts.json
    isolated_manager = HistoryManager(base_dir=tmp_path)
    isolated_manager.save_alert(75, "Suspicious connection on port 4444")

    alerts = isolated_manager.get_alerts()
    assert len(alerts) == 1
    target_ts = alerts[0]["timestamp"]
    target_msg = alerts[0]["message"]

    monkeypatch.setattr("port_dashboard.HistoryManager", lambda *args, **kwargs: isolated_manager)

    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.post(
            "/api/alerts/delete",
            json={"timestamp": target_ts, "message": target_msg},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data.get("deleted") is True
        # Le scan de démarrage peut avoir ajouté ses propres alertes dans le
        # manager isolé — on vérifie la cible précise, pas une liste vide.
        remaining = isolated_manager.get_alerts()
        assert all(
            not (a["timestamp"] == target_ts and a["message"] == target_msg)
            for a in remaining
        )

        # Second appel sur la même alerte déjà supprimée
        resp2 = client.post(
            "/api/alerts/delete",
            json={"timestamp": target_ts, "message": target_msg},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2.get("success") is True
        assert data2.get("deleted") is False


# ---------- T27 : Persistance intrusion + alertes discrètes ----------


def test_intrusion_detector_ban_persistence(tmp_path):
    """Vérifie la réhydratation des bans actifs et l'invalidation des expirés (T27 Spec A)."""
    db_file = tmp_path / "test_intrusion.db"
    config_file = tmp_path / "config.json"
    config_data = {
        "database_path": str(db_file),
        "whitelist": ["127.0.0.1"],
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")

    # Initialisation de la base SQLite via le détecteur
    IntrusionDetector(config_path=str(config_file))

    now = datetime.now()
    future = (now + timedelta(hours=2)).isoformat()
    past = (now - timedelta(hours=2)).isoformat()

    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO banned_ips (ip_address, ban_time, unban_time, reason, attempt_count, is_active)
        VALUES (?, ?, ?, ?, ?, 1)
    """,
        ("198.51.100.1", past, future, "Active brute force", 5),
    )
    cursor.execute(
        """
        INSERT INTO banned_ips (ip_address, ban_time, unban_time, reason, attempt_count, is_active)
        VALUES (?, ?, ?, ?, ?, 1)
    """,
        ("198.51.100.2", past, past, "Expired scan", 10),
    )
    conn.commit()
    conn.close()

    # Redémarrage du détecteur
    reloaded_detector = IntrusionDetector(config_path=str(config_file))

    # L'IP active doit être rechargée dans banned_ips
    assert "198.51.100.1" in reloaded_detector.banned_ips
    assert reloaded_detector.banned_ips["198.51.100.1"].reason == "Active brute force"
    assert reloaded_detector.is_banned("198.51.100.1") is True

    # L'IP expirée ne doit pas être rechargée
    assert "198.51.100.2" not in reloaded_detector.banned_ips
    assert reloaded_detector.is_banned("198.51.100.2") is False

    # L'IP expirée doit avoir été mise à jour à is_active=0 en base
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute("SELECT is_active FROM banned_ips WHERE ip_address = ?", ("198.51.100.2",))
    row = cursor.fetchone()
    conn.close()
    assert row is not None and row[0] == 0


def test_intrusion_detector_whitelist_persistence(tmp_path):
    """Vérifie la persistance de la whitelist sur disque JSON (T27 Spec B)."""
    db_file = tmp_path / "test_intrusion.db"
    config_file = tmp_path / "config.json"
    config_data = {
        "database_path": str(db_file),
        "whitelist": ["127.0.0.1", "10.0.0.1"],
    }
    config_file.write_text(json.dumps(config_data), encoding="utf-8")

    detector = IntrusionDetector(config_path=str(config_file))
    assert "192.168.1.50" not in detector.whitelist

    detector.add_to_whitelist("192.168.1.50")
    assert "192.168.1.50" in detector.whitelist

    # Relire le fichier JSON pour s'assurer de la persistance
    saved = json.loads(config_file.read_text(encoding="utf-8"))
    assert "192.168.1.50" in saved["whitelist"]
    assert saved["whitelist"] == sorted(saved["whitelist"])

    # Retrait persistant
    detector.remove_from_whitelist("10.0.0.1")
    assert "10.0.0.1" not in detector.whitelist
    saved2 = json.loads(config_file.read_text(encoding="utf-8"))
    assert "10.0.0.1" not in saved2["whitelist"]


def test_risk_evaluator_unexpected_port_alert():
    """Vérifie l'alerte insecure_port pour un port LISTEN inattendu et sa déduplication (T27 Spec D)."""
    evaluator = RiskEvaluator({})

    net_data = {
        "timestamp": "2026-09-20T00:00:00",
        "ports": [
            {
                "proto": "tcp",
                "protocol": "tcp",
                "local_address": "0.0.0.0",
                "ip": "0.0.0.0",
                "local_ip": "0.0.0.0",
                "port": 9090,
                "state": "LISTEN",
                "status": "LISTEN",
                "pid": 5678,
                "process": {"name": "rogue_server.exe", "pid": 5678},
                "process_name": "rogue_server.exe",
            }
        ],
        "exposed_ports": [],
    }

    mock_analysis = {
        "risk_score": 30,
        "critical_exposed": [],
        "unexpected_exposed": [
            {"port": 9090, "protocol": "tcp", "local_ip": "0.0.0.0"}
        ],
    }

    with patch.object(evaluator._analyzer, "analyze_risks", return_value=mock_analysis):
        # 1er evaluate : alerte émise 1 fois
        res1 = evaluator.evaluate(net_data)
        alerts1 = [a for a in res1.get("alerts", []) if a.get("type") == "insecure_port"]
        assert len(alerts1) == 1
        a = alerts1[0]
        assert a["severity"] == "warning"
        assert a["port"] == 9090
        assert a["process"] == "rogue_server.exe"
        assert a["pid"] == 5678
        assert "Port 9090/tcp non securise expose par rogue_server.exe" in a["message"]

        # 2e evaluate : déjà dédupliqué -> 0 alerte insecure_port
        res2 = evaluator.evaluate(net_data)
        alerts2 = [a for a in res2.get("alerts", []) if a.get("type") == "insecure_port"]
        assert len(alerts2) == 0


def test_intrusion_detector_alert_callback(tmp_path):
    """Vérifie le callback d'alerte lors d'un ban (T27 Spec C)."""
    db_file = tmp_path / "test_intrusion.db"
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"database_path": str(db_file), "whitelist": []}), encoding="utf-8")

    detector = IntrusionDetector(config_path=str(config_file))
    received_alerts = []
    detector.alert_callback = lambda score, msg: received_alerts.append((score, msg))

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="FAILED_LOGIN_RDP",
        source_ip="203.0.113.10",
        target_service="RDP",
        details="Login failed test",
        severity="HIGH",
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = "No rules match"
        detector._ban_ip("203.0.113.10", "Brute force test", [event])

    assert len(received_alerts) == 1
    score, msg = received_alerts[0]
    assert score == 90
    assert "Intrusion detectee : IP 203.0.113.10 bannie - Brute force test" in msg


# ---------- T31 : Filtrage DNS & Trackers ----------

def test_audit_plan_uses_live_snapshot_without_audit_file(tmp_path, monkeypatch):
    """Le plan d'audit fonctionne en mode installé sans audit_data.json."""
    from port_dashboard import generate_audit_hardening_plan

    plans_dir = tmp_path / "plans"
    plans_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(port_dashboard.paths, "writable_root", lambda: tmp_path)
    monkeypatch.setattr(port_dashboard.paths, "plans_dir", lambda: plans_dir)
    monkeypatch.setattr(
        port_dashboard.paths,
        "scripts_dir",
        lambda: PROJECT_ROOT / "scripts",
    )
    monkeypatch.setattr(
        port_dashboard,
        "_snapshot",
        {
            "ports": [
                {"port": 8080, "protocol": "tcp", "local_ip": "0.0.0.0", "firewall_blocked": False},
                {"port": 443, "protocol": "tcp", "local_ip": "0.0.0.0", "firewall_blocked": True},
            ]
        },
    )

    result = asyncio.run(generate_audit_hardening_plan())
    plan = json.loads((plans_dir / "hardening_plan.json").read_text(encoding="utf-8"))
    assert result["success"] is True
    assert plan["ports"] == [{"port": 8080, "protocol": "tcp", "risk": "unexpected"}]


def test_filter_status_reports_windivert_initialization_error(monkeypatch):
    """Le statut ne doit pas déclarer le filtre actif après un échec WinDivert."""
    class FailedSinkhole:
        running = False
        domaines = {"example.test"}
        whitelist = set()
        initialization_error = "[WinError 5] Accès refusé"
        stats = {"queries_total": 0, "blocked_total": 0}

    monkeypatch.setattr(port_dashboard, "_sinkhole", FailedSinkhole())
    monkeypatch.setattr(port_dashboard, "_load_filter_state", lambda: {"enabled": True})
    result = asyncio.run(port_dashboard.get_filter_status())
    assert result["enabled"] is False
    assert result["running"] is False
    assert "WinError 5" in result["error"]


def test_filter_endpoints_isolated(tmp_path, monkeypatch):
    """Vérifie le cycle complet des endpoints de filtrage trackers (T31)."""
    from collections import Counter
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    # Isoler les fichiers d'état dans tmp_path
    state_file = tmp_path / "filter_state.json"
    wl_file = tmp_path / "filter_whitelist.json"
    monkeypatch.setattr(port_dashboard, "_get_filter_state_file", lambda: state_file)
    monkeypatch.setattr(port_dashboard, "_get_filter_whitelist_file", lambda: wl_file)

    # Neutraliser un éventuel sinkhole réel démarré par le startup d'un test précédent
    if port_dashboard._sinkhole is not None:
        try:
            port_dashboard._sinkhole.stop()
        except Exception:
            pass
        port_dashboard._sinkhole = None

    client = TestClient(app)

    # 1. GET /api/filter/status par défaut (inactif)
    res = client.get("/api/filter/status")
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is False
    assert data["running"] is False
    assert data["domains_count"] == 0
    assert data["queries_total"] == 0
    assert data["blocked_total"] == 0
    assert data["whitelist_count"] >= 88  # Domaines par défaut embarqués

    # 2. GET /api/filter/stats par défaut
    res_stats = client.get("/api/filter/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert stats_data["blocked_total"] == 0
    assert stats_data["queries_total"] == 0
    assert stats_data["top_domains"] == []

    # 3. Whitelist: GET, POST add, POST remove (nouvelle forme structurée T35)
    res_wl = client.get("/api/filter/whitelist")
    assert res_wl.status_code == 200
    wl_data = res_wl.json()
    assert "defaults" in wl_data and len(wl_data["defaults"]) >= 88
    assert "google.com" in wl_data["defaults"]
    assert wl_data["custom"] == []
    assert wl_data["disabled_defaults"] == []

    # Ajouter des domaines
    res_add1 = client.post("/api/filter/whitelist", json={"domain": "Allowed.com", "action": "add"})
    assert res_add1.status_code == 200
    assert "allowed.com" in res_add1.json()["custom"]

    res_add2 = client.post("/api/filter/whitelist", json={"domain": "good-tracker.org", "action": "add"})
    assert res_add2.status_code == 200
    assert len(res_add2.json()["custom"]) == 2

    # Vérifier persistance
    res_wl_check = client.get("/api/filter/whitelist")
    assert res_wl_check.status_code == 200
    assert res_wl_check.json()["custom"] == ["allowed.com", "good-tracker.org"]

    # Retirer un domaine custom
    res_rem = client.post("/api/filter/whitelist", json={"domain": "allowed.com", "action": "remove"})
    assert res_rem.status_code == 200
    assert res_rem.json()["custom"] == ["good-tracker.org"]


    # 4. Mock DnsSinkhole & start
    class MockSinkhole:
        def __init__(self, domaines, whitelist=None, alert_callback=None, domain_meta=None, state_dir=None, **kwargs):
            self.domaines = set(domaines)
            self.whitelist = set(whitelist or [])
            self.alert_callback = alert_callback
            self.domain_meta = domain_meta or {}
            self.running = False
            self.stats = {
                "blocked_total": 42,
                "queries_total": 100,
                "blocked_domains": Counter({"ad.doubleclick.net": 30, "telemetry.bad.org": 12}),
                "blocked_detail": {
                    "ad.doubleclick.net": {
                        "count": 30,
                        "matched_domain": "doubleclick.net",
                        "sources": ["easylist"],
                        "rule": "||doubleclick.net^",
                    },
                    "telemetry.bad.org": {
                        "count": 12,
                        "matched_domain": "bad.org",
                        "sources": ["easyprivacy"],
                        "rule": "||bad.org^",
                    },
                },
            }
        def start(self):
            self.running = True
        def stop(self):
            self.running = False

    monkeypatch.setattr(port_dashboard, "DnsSinkhole", MockSinkhole)
    monkeypatch.setattr(port_dashboard, "load_domain_set", lambda s, max_age_days=7: {"ad.doubleclick.net", "telemetry.bad.org"})
    monkeypatch.setattr(port_dashboard, "load_domain_map", lambda s, max_age_days=7: (
        {"ad.doubleclick.net", "telemetry.bad.org"},
        {
            "doubleclick.net": {"sources": ["easylist"], "rule": "||doubleclick.net^"},
            "bad.org": {"sources": ["easyprivacy"], "rule": "||bad.org^"}
        }
    ))
    # Neutraliser le gestionnaire de listes adblock : sinon ses caches réels
    # (~100k domaines) fusionnent dans _load_combined_domain_map.
    monkeypatch.setattr(port_dashboard, "AdblockListManager", None)
    monkeypatch.setattr(port_dashboard, "_adblock_manager", None)
    # Un sinkhole réel peut avoir été créé par le startup d'un test précédent
    port_dashboard._sinkhole = None

    # POST /api/filter/start
    res_start = client.post("/api/filter/start")
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["success"] is True
    assert start_data["enabled"] is True
    assert start_data["running"] is True

    # Vérifier que le statut reflète le sinkhole actif
    res_status2 = client.get("/api/filter/status")
    assert res_status2.status_code == 200
    s2 = res_status2.json()
    assert s2["enabled"] is True
    assert s2["running"] is True
    assert s2["domains_count"] == 2
    assert s2["blocked_total"] == 42
    assert s2["queries_total"] == 100
    assert s2["whitelist_count"] == len(res_wl_check.json()["defaults"]) + 1

    # Vérifier stats avec top_domains
    res_stats2 = client.get("/api/filter/stats")
    assert res_stats2.status_code == 200
    stats2 = res_stats2.json()
    assert stats2["blocked_total"] == 42
    assert len(stats2["top_domains"]) == 2
    assert stats2["top_domains"][0][0] == "ad.doubleclick.net"
    assert stats2["top_domains"][0][1] == 30

    # Vérifier endpoint /api/filter/blocked (T34)
    res_blocked = client.get("/api/filter/blocked")
    assert res_blocked.status_code == 200
    blocked_items = res_blocked.json()
    assert len(blocked_items) == 2
    assert blocked_items[0]["domain"] == "ad.doubleclick.net"
    assert blocked_items[0]["count"] == 30
    assert blocked_items[0]["matched_domain"] == "doubleclick.net"
    assert blocked_items[0]["sources"] == ["easylist"]
    assert blocked_items[0]["rule"] == "||doubleclick.net^"
    assert blocked_items[1]["domain"] == "telemetry.bad.org"
    assert blocked_items[1]["count"] == 12

    # Whitelist add synchronise sinkhole.whitelist
    client.post("/api/filter/whitelist", json={"domain": "partner.net", "action": "add"})
    assert "partner.net" in port_dashboard._sinkhole.whitelist

    # POST /api/filter/stop
    res_stop = client.post("/api/filter/stop")
    assert res_stop.status_code == 200
    stop_data = res_stop.json()
    assert stop_data["success"] is True
    assert stop_data["enabled"] is False
    assert stop_data["running"] is False
    assert port_dashboard._sinkhole is None

    # Nettoyage global
    port_dashboard._sinkhole = None





# ---------- T28-T30 : tracker_filter (parser ABP + sinkhole DNS) ----------


def test_easylist_parse_domains():
    """Extraction des domaines ||x^ en ignorant commentaires/exceptions/cosmétiques/regex."""
    from tracker_filter.easylist_parser import parse_domains

    sample = """! commentaire
[Adblock Plus]
||ads.example.com^
@@||allowed.example.com^
##.ad-banner
||tracker.net^$third-party
/sub.*regex/
||cdn.bad.org/path.js
||UPPER.Example.COM^
"""
    domains = parse_domains(sample)
    assert "ads.example.com" in domains
    assert "tracker.net" in domains
    assert "upper.example.com" in domains
    # Les règles de chemin ne doivent PAS bloquer le domaine entier
    assert "cdn.bad.org" not in domains
    assert "allowed.example.com" not in domains
    assert not any(d.startswith("/") for d in domains)


def test_sinkhole_dns_parse_and_forge():
    """Parsing d'une vraie requête DNS + forge de la réponse 0.0.0.0 (T30)."""
    from tracker_filter.dns_sinkhole import DnsSinkhole

    # Requête DNS factice : txid=0x1234, flags=0x0100, qd=1, QNAME=ads.example.com, A IN
    qname = b""
    for label in "ads.example.com".split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

    txid, domain, qsection = DnsSinkhole._parse_dns_query(query)
    assert txid == b"\x12\x34"
    assert domain == "ads.example.com"
    assert qsection == qname + struct.pack("!HH", 1, 1)

    resp = DnsSinkhole._build_sinkhole_response(txid, qsection)
    assert resp[:2] == b"\x12\x34"                    # même txid
    flags = struct.unpack("!H", resp[2:4])[0]
    assert flags == 0x8180                             # réponse standard sans erreur
    assert struct.unpack("!H", resp[6:8])[0] == 1      # ancount = 1
    assert resp[-4:] == socket.inet_aton("0.0.0.0")    # sinkhole


def test_sinkhole_fail_open_and_blocking():
    """_is_blocked : suffixe parent bloqué, whitelist prioritaire, domaine sain libre."""
    from tracker_filter.dns_sinkhole import DnsSinkhole

    sink = DnsSinkhole(domaines={"tracker.net", "ads.example.com"}, whitelist={"safe.ads.example.com"})
    assert sink._is_blocked("tracker.net") is True
    assert sink._is_blocked("sub.tracker.net") is True      # suffixe parent
    assert sink._is_blocked("ads.example.com") is True
    assert sink._is_blocked("safe.ads.example.com") is False  # whitelist
    assert sink._is_blocked("legit-site.fr") is False
    assert sink._is_blocked("com") is False                  # TLD jamais bloqué

    # alert_callback dédupliqué par domaine
    alerts = []
    sink2 = DnsSinkhole(domaines={"t.net"}, alert_callback=lambda s, m: alerts.append((s, m)))
    assert sink2.alert_callback is not None


def test_sinkhole_stop_without_start():
    """stop() sans start() ne doit pas lever d'exception (fail-safe)."""
    from tracker_filter.dns_sinkhole import DnsSinkhole
    DnsSinkhole(domaines=set()).stop()  # ne doit pas planter


# ---------- T34 : Traçage de la source des blocages DNS (EasyList parser + Sinkhole) ----------


def test_easylist_parse_domains_meta():
    """parse_domains_meta extrait les domaines avec source et règle originale tronquée à 120 chars."""
    from tracker_filter.easylist_parser import parse_domains_meta

    sample = """! En-tête
[Adblock Plus 2.0]
||track.adserver.com^$third-party
@@||whitelisted.com^
##.ads-banner
||analytics.tracker.net^
/regex/
||toolongrule.com^""" + ("x" * 150)

    meta = parse_domains_meta(sample, "easyprivacy")
    assert "track.adserver.com" in meta
    assert meta["track.adserver.com"]["sources"] == ["easyprivacy"]
    assert meta["track.adserver.com"]["rule"] == "||track.adserver.com^$third-party"

    assert "analytics.tracker.net" in meta
    assert meta["analytics.tracker.net"]["sources"] == ["easyprivacy"]
    assert meta["analytics.tracker.net"]["rule"] == "||analytics.tracker.net^"

    assert "toolongrule.com" in meta
    assert len(meta["toolongrule.com"]["rule"]) <= 120

    assert "whitelisted.com" not in meta
    assert "ads-banner" not in meta


def test_easylist_load_domain_map(tmp_path, monkeypatch):
    """load_domain_map fusionne les sources, persiste domains_meta.json et réutilise le cache."""
    from tracker_filter.easylist_parser import load_domain_map, load_domain_set

    filter_dir = tmp_path / "filter_lists"
    filter_dir.mkdir(parents=True)

    # Préparer deux listes factices
    easylist_file = filter_dir / "easylist.txt"
    easyprivacy_file = filter_dir / "easyprivacy.txt"

    easylist_file.write_text("||shared.tracker.com^\n||only.easylist.com^\n", encoding="utf-8")
    easyprivacy_file.write_text("||shared.tracker.com^\n||only.privacy.org^\n", encoding="utf-8")

    monkeypatch.setattr(
        "tracker_filter.easylist_parser.download_lists",
        lambda s: [str(easylist_file), str(easyprivacy_file)],
    )

    domains, meta = load_domain_map(str(tmp_path), max_age_days=7)

    assert domains == {"shared.tracker.com", "only.easylist.com", "only.privacy.org"}
    assert "shared.tracker.com" in meta
    # Les sources de shared.tracker.com doivent cumuler easylist et easyprivacy
    assert set(meta["shared.tracker.com"]["sources"]) == {"easylist", "easyprivacy"}
    assert meta["only.easylist.com"]["sources"] == ["easylist"]
    assert meta["only.privacy.org"]["sources"] == ["easyprivacy"]

    # Vérifier persistance
    domains_txt = filter_dir / "domains.txt"
    domains_meta_json = filter_dir / "domains_meta.json"
    assert domains_txt.is_file()
    assert domains_meta_json.is_file()

    # Recharger depuis le cache
    cached_domains, cached_meta = load_domain_map(str(tmp_path), max_age_days=7)
    assert cached_domains == domains
    assert cached_meta == meta

    # load_domain_set retourne le même ensemble
    assert load_domain_set(str(tmp_path), max_age_days=7) == domains


def test_sinkhole_blocked_detail_and_meta():
    """DnsSinkhole enregistre le candidat matché, le compte et les métadonnées dans blocked_detail."""
    from tracker_filter.dns_sinkhole import DnsSinkhole

    domain_meta = {
        "adserver.com": {
            "sources": ["easylist", "easyprivacy"],
            "rule": "||adserver.com^$third-party",
        },
        "tracker.org": {
            "sources": ["easyprivacy"],
            "rule": "||tracker.org^",
        },
    }

    sink = DnsSinkhole(
        domaines={"adserver.com", "tracker.org"},
        whitelist={"safe.adserver.com"},
        domain_meta=domain_meta,
    )

    # Test _match avec suffixe parent
    assert sink._match("sub.adserver.com") == "adserver.com"
    assert sink._match("safe.adserver.com") is None
    assert sink._match("unknown.com") is None

    # Simuler la méthode _handle_packet avec un paquet fictif
    class DummyPacket:
        def __init__(self, query_bytes):
            self.is_udp = True
            self.protocol = 17
            self.payload = query_bytes
            self.src_addr = "192.168.1.10"
            self.dst_addr = "192.168.1.1"
            self.src_port = 54321
            self.dst_port = 53
            self.direction = None

        def recalculate_checksums(self):
            pass

    class DummyWinDivert:
        def __init__(self):
            self.sent = []

        def send(self, pkt):
            self.sent.append(pkt)

    def make_dns_query(domain_str):
        qname = b""
        for label in domain_str.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        return struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

    w = DummyWinDivert()

    # 1. Requête bloquée pour sub.adserver.com
    pkt1 = DummyPacket(make_dns_query("sub.adserver.com"))
    sink._handle_packet(w, pkt1)

    assert sink.stats["blocked_total"] == 1
    assert sink.stats["blocked_domains"]["sub.adserver.com"] == 1
    detail = sink.stats["blocked_detail"]["sub.adserver.com"]
    assert detail["count"] == 1
    assert detail["matched_domain"] == "adserver.com"
    assert detail["sources"] == ["easylist", "easyprivacy"]
    assert detail["rule"] == "||adserver.com^$third-party"

    # 2. Deuxième requête pour le même sous-domaine -> incrémente count
    pkt2 = DummyPacket(make_dns_query("sub.adserver.com"))
    sink._handle_packet(w, pkt2)
    assert sink.stats["blocked_total"] == 2
    assert sink.stats["blocked_detail"]["sub.adserver.com"]["count"] == 2

    # 3. Requête saine -> pas bloquée
    pkt3 = DummyPacket(make_dns_query("clean.example.org"))
    sink._handle_packet(w, pkt3)
    assert sink.stats["blocked_total"] == 2
    assert "clean.example.org" not in sink.stats["blocked_detail"]


def test_endpoint_filter_blocked_fallback_to_counter(monkeypatch):
    """GET /api/filter/blocked se replie sur stats['blocked_domains'] si blocked_detail est absent."""
    from collections import Counter
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    class MockSinkholeWithoutDetail:
        def __init__(self, domaines, whitelist=None, alert_callback=None, domain_meta=None):
            self.domaines = set(domaines)
            self.whitelist = set(whitelist or [])
            self.alert_callback = alert_callback
            self.domain_meta = {}
            self.running = True
            self.stats = {
                "blocked_total": 5,
                "queries_total": 20,
                "blocked_domains": Counter({"fallback.ad.com": 5}),
                "blocked_detail": {},  # vide -> fallback sur Counter
            }

        def start(self):
            pass

        def stop(self):
            pass

    port_dashboard._sinkhole = MockSinkholeWithoutDetail(["fallback.ad.com"])

    client = TestClient(app)
    res = client.get("/api/filter/blocked")
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 1
    assert items[0]["domain"] == "fallback.ad.com"
    assert items[0]["count"] == 5
    assert items[0]["matched_domain"] == "fallback.ad.com"
    assert items[0]["sources"] == []
    assert items[0]["rule"] == ""

    # Nettoyage
    port_dashboard._sinkhole = None


def test_endpoint_filter_blocked_whitelisted_flag(monkeypatch):
    """GET /api/filter/blocked marque whitelisted=True pour les domaines deja autorises."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    class MockSinkhole:
        def __init__(self):
            self.whitelist = set()
            self.stats = {
                "blocked_total": 3,
                "queries_total": 10,
                "blocked_domains": {},
                "blocked_detail": {
                    "sub.tracker.com": {
                        "count": 2, "matched_domain": "tracker.com",
                        "sources": ["easyprivacy"], "rule": "||tracker.com^",
                    },
                    "api.allowed.com": {
                        "count": 1, "matched_domain": "api.allowed.com",
                        "sources": ["easylist"], "rule": "||api.allowed.com^",
                    },
                },
            }
        def start(self): pass
        def stop(self): pass

    port_dashboard._sinkhole = MockSinkhole()
    # api.allowed.com autorise directement, tracker.com autorise via parent
    monkeypatch.setattr(
        port_dashboard, "_get_effective_whitelist",
        lambda: {"api.allowed.com", "tracker.com"},
    )

    client = TestClient(app)
    res = client.get("/api/filter/blocked")
    assert res.status_code == 200
    items = {i["domain"]: i for i in res.json()}
    assert items["api.allowed.com"]["whitelisted"] is True
    # sub.tracker.com est couvert par la whitelist via son parent tracker.com
    assert items["sub.tracker.com"]["whitelisted"] is True

    port_dashboard._sinkhole = None


def test_endpoint_filter_blocked_not_whitelisted_flag(monkeypatch):
    """GET /api/filter/blocked marque whitelisted=False pour un domaine non autorise."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    class MockSinkhole:
        def __init__(self):
            self.whitelist = set()
            self.stats = {
                "blocked_total": 1,
                "queries_total": 5,
                "blocked_domains": {},
                "blocked_detail": {
                    "ads.tracker.com": {
                        "count": 1, "matched_domain": "tracker.com",
                        "sources": ["easylist"], "rule": "||tracker.com^",
                    },
                },
            }
        def start(self): pass
        def stop(self): pass

    port_dashboard._sinkhole = MockSinkhole()
    monkeypatch.setattr(port_dashboard, "_get_effective_whitelist", lambda: set())

    client = TestClient(app)
    res = client.get("/api/filter/blocked")
    assert res.status_code == 200
    items = res.json()
    assert items[0]["whitelisted"] is False

    port_dashboard._sinkhole = None


# ==============================================================================
# TESTS T35 : Whitelist de domaines d'infrastructure par défaut & gestion avancée
# ==============================================================================

def test_load_default_whitelist_embedded_no_network(tmp_path, monkeypatch):
    """load_default_whitelist retourne les domaines embarqués (sans réseau) et ignore commentaires."""
    from tracker_filter.easylist_parser import load_default_whitelist
    import tracker_filter.easylist_parser as ep

    # Désactiver les URLs distantes pour garantir aucun appel réseau
    monkeypatch.setattr(ep, "ALLOWLIST_URLS", [])

    domains = load_default_whitelist(str(tmp_path))
    assert isinstance(domains, set)
    assert len(domains) >= 88

    # Vérification d'infrastructure majeure
    key_domains = [
        "google.com", "googleapis.com", "microsoft.com", "windows.com",
        "github.com", "cloudflare.com", "apple.com", "mozilla.org",
        "wikipedia.org", "openai.com", "anthropic.com", "stripe.com",
    ]
    for kd in key_domains:
        assert kd in domains, f"Le domaine essentiel {kd} doit être présent dans la whitelist par défaut"

    # Vérifier qu'aucun commentaire ou ligne vide n'est inclus
    assert "" not in domains
    for d in domains:
        assert not d.startswith("#"), f"Ligne de commentaire non filtrée : {d}"


def test_whitelist_defaults_disable_and_rehabilitate(tmp_path, monkeypatch):
    """remove sur un domaine par défaut remplit disabled_defaults, add le réhabilite et whitelist effective l'exclut."""
    from fastapi.testclient import TestClient
    from port_dashboard import app, _get_effective_whitelist
    import port_dashboard

    state_file = tmp_path / "filter_state.json"
    wl_file = tmp_path / "filter_whitelist.json"
    monkeypatch.setattr(port_dashboard, "_get_filter_state_file", lambda: state_file)
    monkeypatch.setattr(port_dashboard, "_get_filter_whitelist_file", lambda: wl_file)

    port_dashboard._sinkhole = None
    client = TestClient(app)

    # 1. Vérifier état initial : google.com est présent dans les defaults et actif
    res_init = client.get("/api/filter/whitelist")
    assert res_init.status_code == 200
    init_data = res_init.json()
    assert "google.com" in init_data["defaults"]
    assert "google.com" not in init_data["disabled_defaults"]
    assert "google.com" in _get_effective_whitelist(str(tmp_path))

    # 2. Supprimer un domaine par défaut (ex: google.com) -> remplit disabled_defaults sans erreur
    res_rem = client.post("/api/filter/whitelist", json={"domain": "google.com", "action": "remove"})
    assert res_rem.status_code == 200
    rem_data = res_rem.json()
    assert rem_data["success"] is True
    assert "google.com" in rem_data["disabled_defaults"]
    assert "google.com" not in rem_data["whitelist"]  # Exclu de la whitelist effective

    # Vérification que la whitelist effective exclut le default désactivé
    effective = _get_effective_whitelist(str(tmp_path))
    assert "google.com" not in effective

    # 3. Réhabilitation via add sur le domaine désactivé
    res_add = client.post("/api/filter/whitelist", json={"domain": "google.com", "action": "add"})
    assert res_add.status_code == 200
    add_data = res_add.json()
    assert add_data["success"] is True
    assert "google.com" not in add_data["disabled_defaults"]
    assert "google.com" in add_data["whitelist"]

    # Vérifier réintégration effective
    assert "google.com" in _get_effective_whitelist(str(tmp_path))


def test_whitelist_sinkhole_sync_on_disable_and_enable(tmp_path, monkeypatch):
    """Vérifie la synchronisation en temps réel de sinkhole.whitelist lors de remove et add."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    state_file = tmp_path / "filter_state.json"
    wl_file = tmp_path / "filter_whitelist.json"
    monkeypatch.setattr(port_dashboard, "_get_filter_state_file", lambda: state_file)
    monkeypatch.setattr(port_dashboard, "_get_filter_whitelist_file", lambda: wl_file)

    class DummySinkhole:
        def __init__(self):
            self.whitelist = set()
            self.running = True

    dummy = DummySinkhole()
    dummy.whitelist = set(port_dashboard._get_effective_whitelist(str(tmp_path)))
    port_dashboard._sinkhole = dummy

    client = TestClient(app)
    assert "github.com" in port_dashboard._sinkhole.whitelist

    # Désactiver github.com
    client.post("/api/filter/whitelist", json={"domain": "github.com", "action": "remove"})
    assert "github.com" not in port_dashboard._sinkhole.whitelist

    # Réhabiliter github.com
    client.post("/api/filter/whitelist", json={"domain": "github.com", "action": "add"})
    assert "github.com" in port_dashboard._sinkhole.whitelist

    # Nettoyage
    port_dashboard._sinkhole = None


def test_filter_whitelist_legacy_format_compatibility(tmp_path, monkeypatch):
    """Vérifie la compatibilité avec un filter_whitelist.json existant sous forme de liste brute."""
    import json
    from port_dashboard import _load_filter_whitelist_config, _load_filter_whitelist, _save_filter_whitelist
    import port_dashboard

    wl_file = tmp_path / "filter_whitelist.json"
    # Écrire l'ancien format liste
    wl_file.write_text(json.dumps(["legacy.domain.org", "internal.safe.local"]), encoding="utf-8")
    monkeypatch.setattr(port_dashboard, "_get_filter_whitelist_file", lambda: wl_file)

    # Chargement
    cfg = _load_filter_whitelist_config()
    assert "custom" in cfg
    assert "legacy.domain.org" in cfg["custom"]
    assert "internal.safe.local" in cfg["custom"]
    assert cfg["disabled_defaults"] == []

    # _load_filter_whitelist() doit renvoyer la liste custom
    custom_list = _load_filter_whitelist()
    assert "legacy.domain.org" in custom_list

    # Sauvegarde et vérification du format migré
    _save_filter_whitelist(custom_list + ["new-domain.com"])
    persisted = json.loads(wl_file.read_text(encoding="utf-8"))
    assert isinstance(persisted, dict)
    assert "custom" in persisted
    assert "disabled_defaults" in persisted
    assert "new-domain.com" in persisted["custom"]



# ==============================================================================
# TESTS T44 : Verrouillage applicatif, parametres et notifications externes
# ==============================================================================

def test_lock_guards_mutating_endpoints(monkeypatch, tmp_path):
    """Quand le verrou est actif, les POST sensibles renvoient 401 sans cookie."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    monkeypatch.setattr(port_dashboard, "_access_enabled", lambda: True)
    port_dashboard._sessions.clear()

    client = TestClient(app)
    res = client.post("/api/filter/whitelist", json={"domain": "x.com", "action": "add"})
    assert res.status_code == 401

    # Les GET restent ouverts (systray, monitoring)
    assert client.get("/api/auth/status").status_code == 200


def test_unlock_with_app_password(monkeypatch, tmp_path):
    """Mot de passe dedie : hash PBKDF2 verifie, session ouverte, lock ferme."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    salt = "aa" * 16
    port_dashboard._runtime_config = {
        "access": {
            "enabled": True,
            "method": "app",
            "app_password_salt": salt,
            "app_password_hash": port_dashboard._hash_app_password("s3cret", salt),
        }
    }
    monkeypatch.setattr(port_dashboard, "_access_enabled", lambda: True)
    port_dashboard._sessions.clear()

    client = TestClient(app)

    # Mauvais mot de passe
    assert client.post("/api/unlock", json={"password": "mauvais"}).status_code == 401

    # Bon mot de passe -> cookie pose
    res = client.post("/api/unlock", json={"password": "s3cret"})
    assert res.status_code == 200 and res.json()["success"] is True

    # Endpoint protege maintenant accessible (cookies TestClient persistants)
    st = client.get("/api/auth/status").json()
    assert st["unlocked"] is True

    # Verrouillage manuel
    assert client.post("/api/lock").status_code == 200
    assert client.get("/api/auth/status").json()["unlocked"] is False

    port_dashboard._runtime_config = None


def test_settings_get_masks_secrets_and_put_persists(monkeypatch, tmp_path):
    """GET /api/settings masque les secrets ; PUT persiste et borne les valeurs."""
    from fastapi.testclient import TestClient
    from port_dashboard import app
    import port_dashboard

    cfg_file = tmp_path / "config.yml"
    monkeypatch.setattr(port_dashboard, "_config_file_path", lambda: cfg_file)
    monkeypatch.setattr(port_dashboard, "_access_enabled", lambda: False)
    port_dashboard._runtime_config = {
        "smtp_password": "motdepasse-secret",
        "scan_interval_seconds": 30,
        "access": {"app_password_hash": "abc", "app_password_salt": "def"},
    }

    client = TestClient(app)

    data = client.get("/api/settings").json()
    assert data["smtp_password"] == "•••"
    assert data["access"]["app_password_hash"] == "•••"

    res = client.put("/api/settings", json={
        "scan_interval_seconds": 45,
        "critical_ports": [22, 443],
        "external_min_severity": 80,
    })
    assert res.status_code == 200
    saved = res.json()
    assert saved["scan_interval_seconds"] == 45
    assert saved["critical_ports"] == [22, 443]

    # Persisté dans le YAML
    import yaml as _yaml
    written = _yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    assert written["scan_interval_seconds"] == 45

    # Bornes : intervalle < 5 remonte a 5
    res2 = client.put("/api/settings", json={"scan_interval_seconds": 1})
    assert res2.json()["scan_interval_seconds"] == 5

    port_dashboard._runtime_config = None


def test_notifier_webhook_and_threshold(monkeypatch):
    """send_external_alert : seuil respecte, webhook appele, fail-open."""
    from web_port_dashboard.notifier import send_external_alert
    import web_port_dashboard.notifier as nt
    import urllib.request

    calls = []

    class FakeResp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=0):
        calls.append(req)
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    # Sous le seuil : aucun appel
    assert send_external_alert({"webhook_url": "http://x/hook", "external_min_severity": 90}, 50, "test") is False
    assert calls == []

    # Au-dessus du seuil : webhook appele
    assert send_external_alert({"webhook_url": "http://x/hook", "external_min_severity": 90}, 95, "critique") is True
    assert len(calls) == 1

    # Fail-open : exception reseau -> False, pas d'exception levee
    def boom(req, timeout=0):
        raise OSError("offline")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert send_external_alert({"webhook_url": "http://x/hook"}, 95, "critique") is False


# ---------- Regression : tempete de notifications au redemarrage ----------

def test_sinkhole_notified_persisted_across_restarts(tmp_path):
    """Les domaines notifies survivent a un redemarrage du sinkhole (pas de
    nouvelle notification Windows pour un domaine deja vu)."""
    from tracker_filter.dns_sinkhole import DnsSinkhole

    s1 = DnsSinkhole(domaines={"tracker.example"}, state_dir=str(tmp_path))
    s1._notified.add("tracker.example")
    s1._save_notified()

    # "Redemarrage" : nouvelle instance sur le meme state_dir
    s2 = DnsSinkhole(domaines={"tracker.example"}, state_dir=str(tmp_path))
    assert "tracker.example" in s2._notified
    assert (tmp_path / "notified_domains.json").is_file()


def test_sinkhole_notified_empty_without_state_dir():
    """Sans state_dir, aucune persistance (comportement degrade, pas de crash)."""
    from tracker_filter.dns_sinkhole import DnsSinkhole

    s = DnsSinkhole(domaines=set())
    s._notified.add("x.example")
    s._save_notified()  # no-op silencieux
    assert s._notified_file is None


def test_risk_evaluator_anomalies_persisted_across_restarts(tmp_path):
    """Une anomalie de port deja signalee ne redeclenche pas d'alerte apres
    recreation de l'evaluateur (redemarrage du backend)."""
    cfg = {"critical_ports": [22]}
    net = _net_data(4444, "ncat.exe")

    e1 = RiskEvaluator(cfg, state_dir=str(tmp_path))
    r1 = e1.evaluate(net)
    assert r1["alerts"], "le premier passage doit produire une alerte"
    assert (tmp_path / "reported_anomalies.json").is_file()

    # "Redemarrage" : nouvel evaluateur, meme state_dir
    e2 = RiskEvaluator(cfg, state_dir=str(tmp_path))
    r2 = e2.evaluate(net)
    assert r2["alerts"] == [], "l'anomalie deja vue ne doit pas re-alerter"


def test_record_alert_dedup_same_message():
    """_record_alert ignore le meme (score, message) dans la fenetre de dedup
    (filet contre les doublons IPv4/IPv6 ou races de scan)."""
    import uuid

    class FakeHistory:
        def __init__(self):
            self.saved = []
        def save_alert(self, score, message):
            self.saved.append((score, message))

    history = FakeHistory()
    msg = f"Port 3342/tcp non securise expose par node.exe ({uuid.uuid4()})"

    port_dashboard._record_alert(history, 50, msg)
    port_dashboard._record_alert(history, 50, msg)

    assert len(history.saved) == 1
    assert history.saved[0] == (50, msg)


def test_filter_inspect_domain_endpoint(monkeypatch):
    """GET /api/filter/inspect/{domain} : validation + délégation à domain_intel."""
    from fastapi.testclient import TestClient
    import port_dashboard as pd

    client = TestClient(pd.app)

    # Domaine invalide -> 400
    res = client.get("/api/filter/inspect/bad%20domain!")
    assert res.status_code == 400

    # module indisponible -> reponse degradee sans crash
    monkeypatch.setattr(pd, "inspect_domain", None)
    res = client.get("/api/filter/inspect/example.com")
    assert res.status_code == 200
    assert res.json()["domain"] == "example.com"

    # module present -> le resultat est relaye (sans reseau reel)
    called = {}
    def fake_inspect(domain, local_detail):
        called["domain"] = domain
        return {"domain": domain, "local": local_detail, "links": {"virustotal": "x"},
                "rdap": {"available": False}, "urlhaus": {"available": False},
                "dns": {"available": False}}
    monkeypatch.setattr(pd, "inspect_domain", fake_inspect)
    res = client.get("/api/filter/inspect/Tracker.Example.COM")
    assert res.status_code == 200
    assert called["domain"] == "tracker.example.com"  # normalise en minuscules
    assert res.json()["links"]["virustotal"] == "x"


def test_shutdown_endpoint_sets_should_exit(monkeypatch):
    """POST /api/shutdown repond 200 et demande l'arret a uvicorn."""
    import time as _time
    from fastapi.testclient import TestClient
    import port_dashboard as pd

    class FakeServer:
        should_exit = False

    fake = FakeServer()
    monkeypatch.setattr(pd, "_uvicorn_server", fake)

    # Neutralise le PIN de shutdown : le test doit être indépendant de l'état
    # réel de parental_rules.json (contrôle parental/domestique actif ou non).
    class _NoProtection:
        def is_enabled(self, scope):
            return False

    monkeypatch.setattr(pd, "_rules_engine", _NoProtection())

    client = TestClient(pd.app)
    res = client.post("/api/shutdown")
    assert res.status_code == 200
    assert res.json()["success"] is True

    _time.sleep(1.0)  # le thread différé a 0.6s de latence
    assert fake.should_exit is True
