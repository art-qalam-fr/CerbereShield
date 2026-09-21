# tests/test_list_updater.py — Suite de tests PRD T66 (mise à jour des listes)
#
# Couvre tracker_filter/list_updater.py :
#   - update_all_lists : rapport consolidé adblock + parental, fail-open par
#     source (une erreur adblock n'empêche pas le parental, et réciproquement),
#     include_parental=False, jamais d'exception ;
#   - ListUpdateScheduler : enabled=False -> start() no-op ; démarrage/arrêt du
#     thread ; exceptions absorbées ; _needs_update (missing/error/âge > 24 h,
#     listes désactivées ignorées, exception -> False) ; config persistée
#     update_scheduler.json prioritaire sur les arguments.
#
# Aucun téléchargement réel : AdblockListManager/ListsManager/update_all_lists
# sont systématiquement remplacés par des stubs via monkeypatch.
import json
import sys
import time
from pathlib import Path

import pytest

# Bootstrap sys.path : racine projet + sous-packages (même pattern que test_security.py)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DASH_ROOT = PROJECT_ROOT / "web_port_dashboard"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts" / "python"

for p in (PROJECT_ROOT, WEB_DASH_ROOT, SCRIPTS_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import parental_control.lists_manager as plm
import tracker_filter.list_manager as lm
import tracker_filter.list_updater as lu
from tracker_filter.list_updater import ListUpdateScheduler, update_all_lists


# ============================ Stubs ============================


def _make_adblock_stub(refresh_result=None, raises=None):
    """Fabrique une classe stub conforme à AdblockListManager (ctor + refresh)."""

    class _StubAdblock:
        def __init__(self, state_dir=None, **kwargs):
            if raises == "init":
                raise RuntimeError("init adblock impossible")

        def refresh(self, list_id=None):
            if raises == "refresh":
                raise RuntimeError("réseau adblock HS")
            return dict(refresh_result or {})

    return _StubAdblock


def _make_parental_stub(refresh_result=None, raises=None, calls=None):
    """Fabrique une classe stub conforme à parental ListsManager."""

    class _StubParental:
        def __init__(self, state_dir=None, **kwargs):
            if calls is not None:
                calls.append(state_dir)
            if raises == "init":
                raise RuntimeError("init parental impossible")

        def refresh(self, categories=None):
            if raises == "refresh":
                raise RuntimeError("réseau parental HS")
            return dict(refresh_result or {})

    return _StubParental


# ============================ update_all_lists ============================


def test_update_all_lists_consolidated_report(tmp_path, monkeypatch):
    """Rapport consolidé : sections adblock + parental, erreurs vides, timestamps."""
    monkeypatch.setattr(
        lm,
        "AdblockListManager",
        _make_adblock_stub({"easylist": {"status": "ok", "domains": 10}}),
    )
    monkeypatch.setattr(
        plm,
        "ListsManager",
        _make_parental_stub({"adult": {"status": "ok", "count": 5}}),
    )

    report = update_all_lists(str(tmp_path))

    assert report["adblock"]["easylist"]["status"] == "ok"
    assert report["adblock"]["easylist"]["domains"] == 10
    assert report["parental"]["adult"]["status"] == "ok"
    assert report["parental"]["adult"]["count"] == 5
    assert report["errors"] == []
    assert "started_at" in report and "finished_at" in report
    assert isinstance(report["duration_s"], float)


def test_update_all_lists_adblock_error_does_not_block_parental(tmp_path, monkeypatch):
    """Une erreur adblock est consignée dans errors[] sans empêcher le parental."""
    monkeypatch.setattr(
        lm, "AdblockListManager", _make_adblock_stub(raises="refresh")
    )
    monkeypatch.setattr(
        plm,
        "ListsManager",
        _make_parental_stub({"adult": {"status": "ok", "count": 3}}),
    )

    report = update_all_lists(str(tmp_path))  # ne doit pas lever

    assert report["adblock"] == {}
    assert report["parental"]["adult"]["status"] == "ok"
    assert len(report["errors"]) == 1
    assert report["errors"][0].startswith("adblock:")


def test_update_all_lists_parental_error_does_not_block_adblock(tmp_path, monkeypatch):
    """Symétrique : une erreur parentale n'empêche pas le rapport adblock."""
    monkeypatch.setattr(
        lm,
        "AdblockListManager",
        _make_adblock_stub({"easylist": {"status": "ok", "domains": 7}}),
    )
    monkeypatch.setattr(
        plm, "ListsManager", _make_parental_stub(raises="refresh")
    )

    report = update_all_lists(str(tmp_path))

    assert report["adblock"]["easylist"]["domains"] == 7
    assert report["parental"] == {}
    assert len(report["errors"]) == 1
    assert report["errors"][0].startswith("parental:")


def test_update_all_lists_include_parental_false(tmp_path, monkeypatch):
    """include_parental=False : ListsManager n'est jamais instancié."""
    calls = []
    monkeypatch.setattr(
        lm,
        "AdblockListManager",
        _make_adblock_stub({"easylist": {"status": "ok", "domains": 1}}),
    )
    monkeypatch.setattr(
        plm, "ListsManager", _make_parental_stub(raises="init", calls=calls)
    )

    report = update_all_lists(str(tmp_path), include_parental=False)

    assert calls == []                       # parental jamais instancié
    assert report["parental"] == {}
    assert report["adblock"]["easylist"]["status"] == "ok"
    assert report["errors"] == []


def test_update_all_lists_both_fail_no_exception(tmp_path, monkeypatch):
    """Double échec -> deux entrées dans errors[], rapport toujours retourné."""
    monkeypatch.setattr(
        lm, "AdblockListManager", _make_adblock_stub(raises="init")
    )
    monkeypatch.setattr(
        plm, "ListsManager", _make_parental_stub(raises="refresh")
    )

    report = update_all_lists(str(tmp_path))

    assert report["adblock"] == {} and report["parental"] == {}
    assert len(report["errors"]) == 2
    assert any(e.startswith("adblock:") for e in report["errors"])
    assert any(e.startswith("parental:") for e in report["errors"])


# ============================ ListUpdateScheduler ============================


def test_scheduler_disabled_start_is_noop(tmp_path):
    """enabled=False -> start() no-op : pas de thread, is_running False."""
    sched = ListUpdateScheduler(state_dir=str(tmp_path), enabled=False)
    sched.start()
    try:
        assert sched.is_running is False
        assert sched._thread is None
    finally:
        sched.stop()  # no-op sûr, ne doit pas lever
    assert sched.is_running is False


def test_scheduler_enabled_starts_runs_and_stops(tmp_path, monkeypatch):
    """enabled=True : thread daemon démarré, _needs_update -> _run_once, stop propre."""
    reports = []

    def fake_update(state_dir):
        reports.append(state_dir)
        return {"errors": [], "duration_s": 0.01, "adblock": {}, "parental": {}}

    monkeypatch.setattr(lu, "update_all_lists", fake_update)
    # Forcer la mise à jour au démarrage (pas d'attente du premier cycle).
    monkeypatch.setattr(ListUpdateScheduler, "_needs_update", lambda self: True)

    sched = ListUpdateScheduler(
        state_dir=str(tmp_path), check_interval_hours=24, enabled=True
    )
    sched.start()
    try:
        assert sched.is_running is True
        deadline = time.time() + 3
        while sched.last_run_report is None and time.time() < deadline:
            time.sleep(0.05)
        assert sched.last_run_report is not None
        assert sched.last_run_report["errors"] == []
        assert reports == [str(tmp_path)]
    finally:
        sched.stop()
    assert sched.is_running is False


def test_scheduler_run_once_absorbs_exceptions(tmp_path, monkeypatch):
    """update_all_lists qui lève -> _run_once avale l'erreur, last_run_report intact."""
    def boom(state_dir):
        raise RuntimeError("mise à jour catastrophique")

    monkeypatch.setattr(lu, "update_all_lists", boom)
    sched = ListUpdateScheduler(state_dir=str(tmp_path), enabled=False)
    sched._run_once()  # ne doit pas lever
    assert sched.last_run_report is None


def test_scheduler_run_once_sets_last_run_report(tmp_path, monkeypatch):
    """_run_once renseigne last_run_report avec le rapport de update_all_lists."""
    expected = {"errors": ["adblock: x"], "duration_s": 1.5}
    monkeypatch.setattr(lu, "update_all_lists", lambda sd: dict(expected))

    sched = ListUpdateScheduler(state_dir=str(tmp_path), enabled=False)
    sched._run_once()
    assert sched.last_run_report == expected


# ---------- _needs_update ----------


def _scheduler_with_status(monkeypatch, tmp_path, status_dict):
    """Scheduler dont AdblockListManager.status() renvoie status_dict."""

    class _StubMgr:
        def __init__(self, state_dir=None, **kwargs):
            pass

        def status(self):
            return dict(status_dict)

    monkeypatch.setattr(lm, "AdblockListManager", _StubMgr)
    return ListUpdateScheduler(state_dir=str(tmp_path), enabled=False)


def test_needs_update_missing_enabled_list(tmp_path, monkeypatch):
    """Liste activée sans cache (missing) -> mise à jour nécessaire."""
    sched = _scheduler_with_status(
        monkeypatch,
        tmp_path,
        {"easylist": {"enabled": True, "status": "missing", "cache_age_hours": None}},
    )
    assert sched._needs_update() is True


def test_needs_update_error_status(tmp_path, monkeypatch):
    """Liste activée en état 'error' -> mise à jour nécessaire."""
    sched = _scheduler_with_status(
        monkeypatch,
        tmp_path,
        {"easylist": {"enabled": True, "status": "error", "cache_age_hours": 2.0}},
    )
    assert sched._needs_update() is True


def test_needs_update_stale_cache_over_24h(tmp_path, monkeypatch):
    """Cache activé plus vieux que 24 h -> mise à jour nécessaire."""
    sched = _scheduler_with_status(
        monkeypatch,
        tmp_path,
        {"easylist": {"enabled": True, "status": "ok", "cache_age_hours": 30.0}},
    )
    assert sched._needs_update() is True


def test_needs_update_fresh_cache_ok(tmp_path, monkeypatch):
    """Toutes les listes activées ont un cache frais (< 24 h) -> pas de mise à jour."""
    sched = _scheduler_with_status(
        monkeypatch,
        tmp_path,
        {
            "easylist": {"enabled": True, "status": "ok", "cache_age_hours": 2.0},
            "easyprivacy": {"enabled": True, "status": "ok", "cache_age_hours": 23.9},
            "oisd_big": {"enabled": False, "status": "ok", "cache_age_hours": 1.0},
        },
    )
    assert sched._needs_update() is False


def test_needs_update_ignores_disabled_lists(tmp_path, monkeypatch):
    """Une liste désactivée sans cache ne déclenche pas de mise à jour."""
    sched = _scheduler_with_status(
        monkeypatch,
        tmp_path,
        {
            "easylist": {"enabled": True, "status": "ok", "cache_age_hours": 1.0},
            "adguard_dns": {"enabled": False, "status": "missing", "cache_age_hours": None},
        },
    )
    assert sched._needs_update() is False


def test_needs_update_exception_returns_false(tmp_path, monkeypatch):
    """Si status() est inaccessible (manager cassé), _needs_update -> False."""

    class _ExplodingMgr:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("manager indisponible")

    monkeypatch.setattr(lm, "AdblockListManager", _ExplodingMgr)
    sched = ListUpdateScheduler(state_dir=str(tmp_path), enabled=False)
    assert sched._needs_update() is False


# ---------- Configuration persistée ----------


def test_scheduler_persisted_config_overrides_args(tmp_path):
    """update_scheduler.json prime sur les arguments enabled/check_interval_hours."""
    cfg_file = tmp_path / "update_scheduler.json"
    cfg_file.write_text(
        json.dumps({"enabled": False, "interval_hours": 12}), encoding="utf-8"
    )

    sched = ListUpdateScheduler(
        state_dir=str(tmp_path), check_interval_hours=24, enabled=True
    )
    assert sched.enabled is False
    assert sched.interval_hours == 12.0
    sched.start()
    assert sched.is_running is False


def test_scheduler_defaults_without_config(tmp_path):
    """Sans fichier de config, les arguments du constructeur sont appliqués."""
    sched = ListUpdateScheduler(
        state_dir=str(tmp_path), check_interval_hours=6, enabled=True
    )
    assert sched.enabled is True
    assert sched.interval_hours == 6.0
    assert sched.last_run_report is None


def test_scheduler_corrupt_config_falls_back(tmp_path):
    """Un update_scheduler.json illisible est ignoré silencieusement."""
    (tmp_path / "update_scheduler.json").write_text("{invalid json", encoding="utf-8")
    sched = ListUpdateScheduler(
        state_dir=str(tmp_path), check_interval_hours=8, enabled=True
    )
    assert sched.enabled is True
    assert sched.interval_hours == 8.0
