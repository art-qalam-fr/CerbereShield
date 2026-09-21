# tests/test_adblock_lists.py — Suite de tests PRD T66 (bloqueur de pub multi-listes)
#
# Couvre tracker_filter/list_manager.py :
#   - parsing ABP (||domaine^, |domaine|, exceptions @@, cosmétiques ##/#?#/#@#,
#     regex /.../, règles de chemin, tolérance hosts « 0.0.0.0 d » et domaines nus) ;
#   - format « domains » (ligne nue, préfixe IP, commentaires #/;/!) ;
#   - expansion « www.x » -> « x » ;
#   - persistance de adblock_config.json via set_enabled() + status() ;
#   - get_domains() = union des listes ACTIVÉES ; get_sources_for() = suffixe parent ;
#   - refresh() fail-open : statut "cached" si cache présent, "error" sinon,
#     jamais d'exception (le code utilise "cached", pas "stale" — "stale"
#     n'apparaît que dans status() pour un cache plus vieux que le TTL) ;
#   - endpoints /api/adblock/* et /api/lists/* via TestClient
#     (même pattern que test_security.py : TestClient SANS context manager,
#     donc sans startup event -> pas de scheduler ni de téléchargement réel).
#
# Tous les états sont isolés dans tmp_path : jamais d'écriture dans
# web_port_dashboard/state/ et JAMAIS de téléchargement réseau (_download mocké).
import json
import os
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

import tracker_filter.list_manager as lm
from tracker_filter.list_manager import (
    LIST_REGISTRY,
    AdblockListManager,
    parse_abp_domains,
    parse_domains_format,
)


# ============================ Helpers / fixtures ============================


def _write_cache(mgr: AdblockListManager, list_id: str, text: str) -> Path:
    """Écrit un fichier de cache de liste directement dans le state_dir isolé."""
    cache_file = mgr._cache_file(list_id)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(text, encoding="utf-8")
    return cache_file


def _failing_download(url, timeout=30):
    """_download factice qui échoue toujours (aucun réseau en test)."""
    raise OSError("réseau désactivé dans les tests")


@pytest.fixture
def manager(tmp_path):
    """AdblockListManager isolé sur tmp_path (registre réel, aucun cache)."""
    return AdblockListManager(state_dir=str(tmp_path))


# ============================ Parsing : format ABP ============================


def test_parse_abp_host_and_exact_rules():
    """||domaine^, ||domaine^$options et |domaine| sont extraits et normalisés."""
    text = """! commentaire de liste
[Adblock Plus 2.0]
||ads.example.com^
||tracker.example.net^$third-party
|exact.match.example.org|
||UPPER.Example.COM^
"""
    domains = parse_abp_domains(text)
    assert "ads.example.com" in domains
    assert "tracker.example.net" in domains
    assert "exact.match.example.org" in domains
    assert "upper.example.com" in domains  # normalisé en minuscules


def test_parse_abp_ignores_exceptions_cosmetic_regex_paths():
    """@@, ##, #?#, #@#, /regex/, chemins et commentaires sont ignorés."""
    text = """@@||allowed.example.com^
##.ad-banner
example.com##.ad-banner
example.com#?#.ad-slot
example.com#@#.sponsor
/regex.*rule/
||cdn.bad.example.org/path.js
||good.example.com^$script,third-party
"""
    domains = parse_abp_domains(text)
    assert "good.example.com" in domains
    assert "allowed.example.com" not in domains
    assert "cdn.bad.example.org" not in domains  # règle de chemin -> pas le domaine entier
    assert not any(d.startswith("/") or "#" in d for d in domains)


def test_parse_abp_hosts_prefix_and_naked_domain():
    """Tolérance : « 0.0.0.0 domaine », domaine nu ; lignes à >2 jetons/IP seule ignorées."""
    text = """0.0.0.0 host-listed.example.com
127.0.0.1 ipv4-listed.example.net
::1 ipv6-listed.example.org
naked-domain.example.io
8.8.8.8
three tokens ignored.example.com
"""
    domains = parse_abp_domains(text)
    assert "host-listed.example.com" in domains
    assert "ipv4-listed.example.net" in domains
    assert "ipv6-listed.example.org" in domains
    assert "naked-domain.example.io" in domains
    assert "ignored.example.com" not in domains  # ligne à 3 jetons ignorée
    assert not any("8.8.8.8" in d for d in domains)


def test_parse_abp_www_expansion():
    """Une entrée « www.x » couvre aussi « x » (expansion vers le domaine nu)."""
    domains = parse_abp_domains("||www.ads.example.com^\nwww.naked.example.org\n")
    assert "www.ads.example.com" in domains
    assert "ads.example.com" in domains          # expansion www.
    assert "www.naked.example.org" in domains
    assert "naked.example.org" in domains        # expansion www.


# ============================ Parsing : format « domains » ============================


def test_parse_domains_format_hosts_and_comments():
    """Format Hagezi domains : ligne nue, préfixe IP, commentaires #/;/! ignorés."""
    text = """# commentaire pleine ligne
; commentaire style hosts
! autre commentaire
0.0.0.0 blocked-one.example.com
naked-two.example.net # commentaire en fin de ligne
www.only-www.example.org

"""
    domains = parse_domains_format(text, "domains")
    assert "blocked-one.example.com" in domains
    assert "naked-two.example.net" in domains
    assert "www.only-www.example.org" in domains
    assert "only-www.example.org" in domains     # expansion www.
    assert not any(d.startswith(("#", ";", "!")) for d in domains)


def test_parse_domains_format_dispatch():
    """parse_domains_format délègue selon fmt : « abp » vs « domains »."""
    # Une règle ||x^ n'est pas un domaine valide au format « domains ».
    assert parse_domains_format("||pipe.example.com^", "abp") == {"pipe.example.com"}
    assert parse_domains_format("||pipe.example.com^", "domains") == set()
    # Un domaine nu est accepté dans les deux formats (fallback tolérant ABP).
    assert "naked.example.com" in parse_domains_format("naked.example.com", "abp")
    assert "naked.example.com" in parse_domains_format("naked.example.com", "domains")


# ============================ Manager : config, statut, domaines ============================


def test_manager_defaults_and_status_shape(manager):
    """Défauts du registre (easylist+easyprivacy) et structure de status()."""
    assert set(manager.enabled_lists()) == {"easylist", "easyprivacy"}

    st = manager.status()
    assert set(st) == set(LIST_REGISTRY)
    for lid, info in st.items():
        assert info["id"] == lid
        assert info["name"] == LIST_REGISTRY[lid]["name"]
        assert info["status"] == "missing"       # aucun cache encore
        assert info["cache_age_hours"] is None
        assert info["last_update"] is None
        assert info["domains_loaded"] == 0
    assert st["easylist"]["enabled"] is True
    assert st["adguard_dns"]["enabled"] is False


def test_set_enabled_persists_and_status_reflects(manager, tmp_path):
    """set_enabled écrit adblock_config.json ; une nouvelle instance recharge l'état."""
    res = manager.set_enabled("hagezi_multi", True)
    assert res["hagezi_multi"]["enabled"] is True

    cfg_file = tmp_path / "adblock_config.json"
    assert cfg_file.is_file()
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert "hagezi_multi" in cfg["enabled"]

    manager.set_enabled("easylist", False)
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert "easylist" not in cfg["enabled"]
    assert manager.status()["easylist"]["enabled"] is False

    # « Redémarrage » : nouvelle instance sur le même state_dir.
    manager2 = AdblockListManager(state_dir=str(tmp_path))
    assert "hagezi_multi" in manager2.enabled_lists()
    assert "easylist" not in manager2.enabled_lists()
    assert "easyprivacy" in manager2.enabled_lists()


def test_set_enabled_unknown_list_raises(manager):
    """Un list_id hors registre lève ValueError (le endpoint le traduit en 400)."""
    with pytest.raises(ValueError):
        manager.set_enabled("liste-inconnue", True)


def test_get_domains_union_of_enabled_only(manager):
    """get_domains() = union des caches des listes ACTIVÉES uniquement."""
    _write_cache(manager, "easylist", "||ads-one.example.com^\n")
    _write_cache(manager, "easyprivacy", "||track-two.example.net^\n")
    _write_cache(manager, "adguard_dns", "||ag-three.example.org^\n")   # désactivée
    _write_cache(manager, "hagezi_multi", "0.0.0.0 hg-four.example.io\nhg-naked.example.fr\n")

    domains = manager.get_domains()
    assert domains == {"ads-one.example.com", "track-two.example.net"}

    manager.set_enabled("adguard_dns", True)
    domains = manager.get_domains()
    assert "ag-three.example.org" in domains

    # La liste au format « domains » (hagezi) est parsée via parse_list_text.
    manager.set_enabled("hagezi_multi", True)
    domains = manager.get_domains()
    assert "hg-four.example.io" in domains
    assert "hg-naked.example.fr" in domains

    # Désactiver une liste retire ses domaines de l'union.
    manager.set_enabled("easylist", False)
    assert "ads-one.example.com" not in manager.get_domains()


def test_get_sources_for_suffix_parent_matching(manager):
    """get_sources_for() remonte les labels : sous-domaine -> listes sources activées."""
    _write_cache(manager, "easylist", "||shared-tracker.example.com^\n")
    _write_cache(manager, "easyprivacy", "||shared-tracker.example.com^\n||only-privacy.example.net^\n")
    _write_cache(manager, "adguard_dns", "||ag-only.example.org^\n")  # désactivée

    # Sous-domaine profond : match par suffixe parent dans les deux listes.
    assert manager.get_sources_for("a.b.shared-tracker.example.com") == [
        "easylist", "easyprivacy",
    ]
    assert manager.get_sources_for("SHARED-TRACKER.example.com.") == [
        "easylist", "easyprivacy",
    ]  # casse + FQDN tolérés
    assert manager.get_sources_for("sub.only-privacy.example.net") == ["easyprivacy"]

    # Liste désactivée : jamais rapportée comme source.
    assert manager.get_sources_for("ag-only.example.org") == []

    # TLD seul / domaine inconnu : aucune source.
    assert manager.get_sources_for("com") == []
    assert manager.get_sources_for("not-shared-tracker.example.com") == []
    assert manager.get_sources_for("") == []


# ============================ refresh() : succès et fail-open ============================


def test_refresh_success_writes_cache(manager, monkeypatch):
    """refresh(list_id) télécharge (mocké), écrit le cache et retourne 'ok'."""
    calls = []

    def fake_download(url, timeout=30):
        calls.append(url)
        return b"||fresh-ads.example.com^\n||www.track.example.org^\n"

    monkeypatch.setattr(lm, "_download", fake_download)
    res = manager.refresh("easylist")

    assert calls == [LIST_REGISTRY["easylist"]["url"]]
    assert res["easylist"]["status"] == "ok"
    assert res["easylist"]["domains"] == 3  # + domaine nu de www.track.example.org
    assert res["easylist"]["updated_at"] is not None
    assert manager._cache_file("easylist").is_file()
    assert "fresh-ads.example.com" in manager.get_domains()
    assert "track.example.org" in manager.get_domains()  # expansion www.


def test_refresh_none_targets_enabled_lists_only(manager, monkeypatch):
    """refresh() sans argument ne rafraîchit que les listes activées."""
    calls = []

    def fake_download(url, timeout=30):
        calls.append(url)
        return b"||x.example.com^\n"

    monkeypatch.setattr(lm, "_download", fake_download)
    res = manager.refresh()

    assert set(res) == {"easylist", "easyprivacy"}  # défauts activés
    assert len(calls) == 2
    assert all(info["status"] == "ok" for info in res.values())


def test_refresh_failopen_serves_existing_cache(manager, monkeypatch):
    """Échec réseau + cache présent -> statut 'cached', domaines servis, pas d'exception."""
    _write_cache(manager, "easylist", "||cached-domain.example.com^\n")
    monkeypatch.setattr(lm, "_download", _failing_download)

    res = manager.refresh("easylist")  # ne doit pas lever
    assert res["easylist"]["status"] == "cached"
    assert res["easylist"]["domains"] == 1
    assert "error" in res["easylist"]
    assert "cached-domain.example.com" in manager.get_domains()


def test_refresh_failopen_error_without_cache(manager, monkeypatch):
    """Échec réseau + pas de cache -> statut 'error', jamais d'exception."""
    monkeypatch.setattr(lm, "_download", _failing_download)

    res = manager.refresh("easylist")
    assert res["easylist"]["status"] == "error"
    assert res["easylist"]["domains"] == 0
    assert "error" in res["easylist"]


def test_refresh_unknown_list(manager, monkeypatch):
    """Un list_id hors registre -> entrée 'error'/'unknown_list', sans réseau."""
    monkeypatch.setattr(lm, "_download", _failing_download)  # ne doit pas être appelé
    res = manager.refresh("inconnue")
    assert res["inconnue"]["status"] == "error"
    assert res["inconnue"]["error"] == "unknown_list"


def test_status_stale_and_error_states(manager):
    """status() : 'stale' si cache > TTL, 'error' si cache présent mais vide de domaines."""
    # Cache périmé (> 7 jours = TTL par défaut).
    old_file = _write_cache(manager, "easylist", "||old.example.com^\n")
    old_ts = time.time() - (8 * 86400)
    os.utime(old_file, (old_ts, old_ts))

    # Cache présent mais ne parsant à aucun domaine -> 'error'.
    _write_cache(manager, "easyprivacy", "! uniquement des commentaires\n##.x\n")

    st = manager.status()
    assert st["easylist"]["status"] == "stale"
    assert st["easylist"]["cache_age_hours"] > 7 * 24
    assert st["easylist"]["domains_loaded"] == 1
    assert st["easyprivacy"]["status"] == "error"
    assert st["easyprivacy"]["domains_loaded"] == 0
    assert st["oisd_big"]["status"] == "missing"  # jamais téléchargée


# ============================ Endpoints FastAPI (TestClient) ============================


class _FakeParentalListsManager:
    """Stub minimal de parental_control.lists_manager.ListsManager."""

    def list_categories(self):
        return {"adult": {"count": 3, "enabled": True, "source": "curated"}}


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """TestClient avec gestionnaires isolés — aucun réseau, aucun état réel."""
    from fastapi.testclient import TestClient
    import port_dashboard

    mgr = AdblockListManager(state_dir=str(tmp_path / "adblock_state"))
    monkeypatch.setattr(port_dashboard, "_adblock_manager", mgr)
    monkeypatch.setattr(port_dashboard, "_sinkhole", None)
    monkeypatch.setattr(port_dashboard, "_list_scheduler", None)
    monkeypatch.setattr(port_dashboard, "_lists_manager", _FakeParentalListsManager())
    # _rules_engine non-None -> _get_rules_engine() n'instancie pas les vrais
    # gestionnaires parentaux (qui écriraient dans web_port_dashboard/state/).
    monkeypatch.setattr(port_dashboard, "_rules_engine", object())
    # Filet de sécurité : tout téléchargement échoue (surchargeable par test).
    monkeypatch.setattr(lm, "_download", _failing_download)
    return TestClient(port_dashboard.app)


def test_endpoint_adblock_lists_200(api_client):
    """GET /api/adblock/lists -> 200, registre complet + état."""
    res = api_client.get("/api/adblock/lists")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert set(data["lists"]) == set(LIST_REGISTRY)
    assert data["lists"]["easylist"]["enabled"] is True
    assert data["lists"]["oisd_big"]["enabled"] is False
    assert data["lists"]["easylist"]["status"] == "missing"


def test_endpoint_adblock_toggle_invalid_list_400(api_client):
    """POST /api/adblock/lists avec list_id inconnu -> 400."""
    res = api_client.post(
        "/api/adblock/lists", json={"list_id": "inconnue", "enabled": True}
    )
    assert res.status_code == 400


def test_endpoint_adblock_toggle_valid(api_client, tmp_path):
    """POST /api/adblock/lists active une liste et persiste la config isolée."""
    res = api_client.post(
        "/api/adblock/lists", json={"list_id": "oisd_big", "enabled": True}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["lists"]["oisd_big"]["enabled"] is True
    assert data["blocked_domains"] == 0  # sinkhole arrêté -> 0

    cfg = json.loads(
        (tmp_path / "adblock_state" / "adblock_config.json").read_text(encoding="utf-8")
    )
    assert "oisd_big" in cfg["enabled"]


def test_endpoint_adblock_lists_unavailable(api_client, monkeypatch):
    """Module adblock indisponible -> GET renvoie available=False, POST -> 501."""
    import port_dashboard

    monkeypatch.setattr(port_dashboard, "AdblockListManager", None)
    monkeypatch.setattr(port_dashboard, "_adblock_manager", None)

    res = api_client.get("/api/adblock/lists")
    assert res.status_code == 200
    assert res.json() == {"available": False, "lists": {}}

    res = api_client.post(
        "/api/adblock/lists", json={"list_id": "easylist", "enabled": True}
    )
    assert res.status_code == 501


def test_endpoint_adblock_update_list(api_client, monkeypatch):
    """POST /api/adblock/lists/update force le refresh (téléchargement mocké)."""
    monkeypatch.setattr(
        lm, "_download", lambda url, timeout=30: b"||endpoint-ads.example.com^\n"
    )
    res = api_client.post("/api/adblock/lists/update", json={"list_id": "easylist"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["report"]["easylist"]["status"] == "ok"
    assert data["report"]["easylist"]["domains"] == 1
    assert data["blocked_domains"] == 0


def test_endpoint_adblock_stats(api_client):
    """GET /api/adblock/stats -> structure agrégée, sinkhole/scheduler arrêtés."""
    res = api_client.get("/api/adblock/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["running"] is False
    assert set(data["enabled_lists"]) == {"easylist", "easyprivacy"}
    assert data["blocked_domains"] == 0
    assert data["blocked_total"] == 0
    assert data["scheduler"]["running"] is False
    assert data["scheduler"]["last_run"] is None


def test_endpoint_lists_status(api_client):
    """GET /api/lists/status -> 200, adblock + catégories parentales agrégées."""
    res = api_client.get("/api/lists/status")
    assert res.status_code == 200
    data = res.json()
    assert set(data["adblock"]) == set(LIST_REGISTRY)
    assert data["parental"] == _FakeParentalListsManager().list_categories()


def test_endpoint_lists_update_all(api_client, monkeypatch):
    """POST /api/lists/update_all -> 200, rapport consolidé (update mocké)."""
    import port_dashboard

    def fake_update_all(state_dir):
        return {
            "started_at": "2026-01-05T12:00:00+00:00",
            "adblock": {"easylist": {"status": "ok", "domains": 10}},
            "parental": {"adult": {"status": "ok", "count": 3}},
            "errors": [],
            "duration_s": 0.01,
            "finished_at": "2026-01-05T12:00:01+00:00",
        }

    monkeypatch.setattr(port_dashboard, "update_all_lists", fake_update_all)
    res = api_client.post("/api/lists/update_all")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["report"]["adblock"]["easylist"]["status"] == "ok"
    assert data["report"]["parental"]["adult"]["count"] == 3
    assert data["report"]["errors"] == []
    assert data["blocked_domains"] == 0
