# tests/test_parental_control.py — Suite de tests contrôle parental/domestique (T52)
#
# Couvre : PinManager (format, lockout persisté), QuotaTracker (minutes uniques,
# rollover à minuit via horloge injectée), RulesEngine (blocked/window/quota,
# fenêtres traversant minuit, priorité domaine > catégorie, matching suffixe),
# DnsSinkhole.rule_resolver (fail-open, blocked_detail enrichi, whitelist du
# filtre tracker non applicable aux règles parentales), CookieScanner, et les
# endpoints /api/parental/*, /api/domestic/*, /api/shutdown (session PIN).
#
# Tous les états sont isolés dans tmp_path : jamais d'écriture dans
# web_port_dashboard/state/.
import json
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Bootstrap sys.path : racine projet + sous-packages (même pattern que test_security.py)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DASH_ROOT = PROJECT_ROOT / "web_port_dashboard"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts" / "python"

for p in (PROJECT_ROOT, WEB_DASH_ROOT, SCRIPTS_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from parental_control.pin_manager import PinManager
from parental_control.quota_tracker import QuotaTracker
from parental_control.rules_engine import Decision, RulesEngine


# ============================ Helpers communs ============================


class MutableClock:
    """Horloge injectable : lire/avancer le temps sans monkeypatch."""

    def __init__(self, now: datetime):
        self._now = now

    def __call__(self) -> datetime:
        return self._now

    def set(self, now: datetime) -> None:
        self._now = now

    def advance(self, **kwargs) -> None:
        self._now += timedelta(**kwargs)


class FakeListsManager:
    """lists_manager factice conforme au contrat du moteur de règles.

    get_domains(cat) -> frozenset, list_categories() -> dict,
    get_all_domains(cats) -> frozenset, refresh() -> no-op compté.
    """

    def __init__(self, mapping=None):
        self._domains = {
            str(k).lower(): frozenset(d.lower() for d in v)
            for k, v in (mapping or {}).items()
        }
        self.refresh_calls = 0

    def get_domains(self, category):
        return self._domains.get(str(category).lower(), frozenset())

    def get_all_domains(self, categories):
        merged = set()
        for cat in categories:
            merged |= set(self.get_domains(cat))
        return frozenset(merged)

    def list_categories(self):
        return {
            cat: {
                "count": len(domains),
                "source": "curated",
                "enabled": bool(domains),
                "cached": False,
                "last_updated": None,
            }
            for cat, domains in self._domains.items()
        }

    def refresh(self, categories=None):
        self.refresh_calls += 1
        return {}


def _make_engine(tmp_path, lists=None, now=None):
    """RulesEngine + QuotaTracker isolés dans tmp_path, horloge partagée."""
    clock = MutableClock(now or datetime(2026, 1, 5, 12, 0))
    quota = QuotaTracker(str(tmp_path), clock=clock)
    engine = RulesEngine(
        lists or FakeListsManager(), quota, str(tmp_path), clock=clock
    )
    return engine, quota, clock


def _dns_query(domain: str, txid: int = 0x4321) -> bytes:
    """Requête DNS A/IN minimale pour `domain` (même format que test_security)."""
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return (
        struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", 1, 1)
    )


class DummyPacket:
    """Paquet WinDivert factice (UDP DNS sortant)."""

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


# ============================ PinManager ============================


def _pin(tmp_path) -> PinManager:
    return PinManager(tmp_path / "parental_pin.json")


def test_pin_set_validates_format(tmp_path):
    """set_pin refuse tout PIN hors 4-8 chiffres, accepte les bornes."""
    pin = _pin(tmp_path)
    for bad in ("", "123", "123456789", "12a4", "abcd", " 1234", "1234 ", None):
        with pytest.raises(ValueError):
            pin.set_pin(bad)
    assert pin.is_set() is False

    pin.set_pin("1234")  # borne basse
    assert pin.is_set() is True

    pin8 = PinManager(tmp_path / "pin8.json")
    pin8.set_pin("12345678")  # borne haute
    assert pin8.verify("12345678") is True


def test_pin_set_only_once(tmp_path):
    """Un second set_pin lève ValueError ; change_pin est la voie de modification."""
    pin = _pin(tmp_path)
    pin.set_pin("1234")
    with pytest.raises(ValueError):
        pin.set_pin("5678")


def test_pin_verify_and_change(tmp_path):
    """verify ok/ko ; change_pin exige l'ancien PIN et un format valide."""
    pin = _pin(tmp_path)
    pin.set_pin("1234")
    assert pin.verify("1234") is True
    assert pin.verify("0000") is False

    # change_pin : mauvais ancien, format invalide, puis succès
    assert pin.change_pin("9999", "5678") is False
    assert pin.change_pin("1234", "abc") is False
    assert pin.change_pin("1234", "5678") is True
    assert pin.verify("1234") is False
    assert pin.verify("5678") is True


def test_pin_never_stored_in_clear(tmp_path):
    """Le fichier d'état contient sel + hash PBKDF2, jamais le PIN en clair."""
    pin = _pin(tmp_path)
    pin.set_pin("4242")
    raw = (tmp_path / "parental_pin.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert "4242" not in raw
    assert data["pin_salt"] and data["pin_hash"]
    assert len(data["pin_hash"]) == 64  # SHA-256 hex


def test_pin_state_reloaded_by_new_instance(tmp_path):
    """Une seconde instance sur le même state_file voit le PIN (reload disque)."""
    _pin(tmp_path).set_pin("1234")
    pin2 = _pin(tmp_path)
    assert pin2.is_set() is True
    assert pin2.verify("1234") is True


def test_pin_lockout_after_five_failures(tmp_path):
    """5 échecs -> verrouillage 30 s : même le bon PIN est refusé."""
    pin = _pin(tmp_path)
    pin.set_pin("1234")
    for _ in range(5):
        assert pin.verify("0000") is False
    remaining = pin.remaining_lockout_seconds()
    assert 0 < remaining <= 31
    assert pin.verify("1234") is False  # verrouillé : le bon PIN échoue aussi


def test_pin_lockout_persisted_across_instances(tmp_path):
    """Le verrou anti brute-force survit à la recréation de l'instance."""
    pin = _pin(tmp_path)
    pin.set_pin("1234")
    for _ in range(5):
        pin.verify("0000")

    pin2 = _pin(tmp_path)  # "redémarrage" sur le même fichier
    assert pin2.remaining_lockout_seconds() > 0
    assert pin2.verify("1234") is False

    # Le compteur/verrouillage sont bien sérialisés dans le JSON
    data = json.loads((tmp_path / "parental_pin.json").read_text(encoding="utf-8"))
    assert data["failed_count"] >= 5
    assert data["locked_until"] > time.time()


# ============================ QuotaTracker ============================


def test_quota_counts_unique_minutes(tmp_path):
    """note_activity dédoublonne la minute courante ; minutes distinctes cumulent."""
    clock = MutableClock(datetime(2026, 1, 5, 10, 30))
    qt = QuotaTracker(str(tmp_path), clock=clock)

    assert qt.note_activity("dom:x.com") == 1
    assert qt.note_activity("dom:x.com") == 1  # même minute -> pas de double compte
    clock.advance(minutes=1)
    assert qt.note_activity("dom:x.com") == 2
    clock.advance(minutes=1)
    assert qt.note_activity("dom:x.com") == 3
    assert qt.used_minutes("dom:x.com") == 3
    assert qt.used_minutes("dom:autre.com") == 0


def test_quota_status_returns_today_map(tmp_path):
    """status() -> {clé: minutes} pour aujourd'hui seulement."""
    clock = MutableClock(datetime(2026, 1, 5, 10, 30))
    qt = QuotaTracker(str(tmp_path), clock=clock)
    qt.note_activity("cat:adult")
    clock.advance(minutes=1)
    qt.note_activity("cat:adult")
    qt.note_activity("dom:y.com")
    assert qt.status() == {"cat:adult": 2, "dom:y.com": 1}


def test_quota_day_rollover_resets(tmp_path):
    """À minuit, le compteur repart à zéro (nouvelle clé de jour)."""
    clock = MutableClock(datetime(2026, 1, 5, 23, 59))
    qt = QuotaTracker(str(tmp_path), clock=clock)
    qt.note_activity("dom:x.com")
    assert qt.used_minutes("dom:x.com") == 1

    clock.advance(minutes=2)  # 2026-01-06 00:01
    assert qt.used_minutes("dom:x.com") == 0
    assert qt.status() == {}
    assert qt.note_activity("dom:x.com") == 1


def test_quota_persisted_and_old_days_purged(tmp_path):
    """L'état survit à la recréation ; les jours < aujourd'hui sont purgés."""
    clock = MutableClock(datetime(2026, 1, 5, 10, 30))
    qt = QuotaTracker(str(tmp_path), clock=clock)
    qt.note_activity("dom:x.com")

    # Injecter un jour ancien directement dans le fichier puis recharger
    usage_file = tmp_path / "quota_usage.json"
    data = json.loads(usage_file.read_text(encoding="utf-8"))
    data["2020-01-01"] = {"dom:x.com": ["10:00", "10:01"]}
    usage_file.write_text(json.dumps(data), encoding="utf-8")

    qt2 = QuotaTracker(str(tmp_path), clock=clock)
    assert qt2.used_minutes("dom:x.com") == 1  # aujourd'hui conservé
    assert "2020-01-01" not in qt2._usage       # jour ancien purgé au chargement


def test_quota_max_minutes_cap(tmp_path):
    """max_minutes_per_day borne le compteur (garde-fou)."""
    clock = MutableClock(datetime(2026, 1, 5, 10, 30))
    qt = QuotaTracker(str(tmp_path), clock=clock, max_minutes_per_day=2)
    assert qt.note_activity("k") == 1
    clock.advance(minutes=1)
    assert qt.note_activity("k") == 2
    clock.advance(minutes=1)
    assert qt.note_activity("k") == 2  # plafond atteint
    assert qt.used_minutes("k") == 2


# ============================ RulesEngine ============================


def test_rules_disabled_scope_allows_everything(tmp_path):
    """Scope désactivé -> aucune règle n'est appliquée."""
    lists = FakeListsManager({"adult": {"bad.example.com"}})
    engine, _, _ = _make_engine(tmp_path, lists)
    engine.update_scope("parental", {"adult": {"mode": "blocked"}}, {})
    d = engine.decide("bad.example.com")
    assert d.blocked is False and d.scope == ""


def test_rules_blocked_category(tmp_path):
    """Mode 'blocked' sur catégorie -> Decision bloquée avec métadonnées."""
    lists = FakeListsManager({"adult": {"bad.example.com"}})
    engine, _, _ = _make_engine(tmp_path, lists)
    engine.set_scope_enabled("parental", True)
    engine.update_scope("parental", {"adult": {"mode": "blocked"}}, {})

    d = engine.decide("bad.example.com")
    assert d.blocked is True
    assert d.scope == "parental"
    assert d.rule_key == "cat:adult"
    assert d.matched == "bad.example.com"
    assert d.mode == "blocked"
    assert d.reason


def test_rules_suffix_matching(tmp_path):
    """Un sous-domaine hérite de la règle du domaine parent ; le TLD seul non."""
    lists = FakeListsManager({"adult": {"bad.example.com"}})
    engine, _, _ = _make_engine(tmp_path, lists)
    engine.set_scope_enabled("parental", True)
    engine.update_scope("parental", {"adult": {"mode": "blocked"}}, {})

    assert engine.decide("www.bad.example.com").blocked is True
    assert engine.decide("a.b.bad.example.com").blocked is True
    assert engine.decide("bad.example.com.").blocked is True  # FQDN trailing dot
    assert engine.decide("BAD.EXAMPLE.COM").blocked is True    # casse
    assert engine.decide("notbad.example.com").blocked is False
    assert engine.decide("com").blocked is False               # TLD jamais matché
    assert engine.decide("clean.example.org").blocked is False


def test_rules_domain_rule_priority_over_category(tmp_path):
    """Règle de domaine personnalisée prioritaire sur la règle de catégorie."""
    lists = FakeListsManager({"adult": {"bad.example.com"}})
    engine, _, _ = _make_engine(tmp_path, lists, now=datetime(2026, 1, 5, 12, 0))
    engine.set_scope_enabled("parental", True)
    engine.update_scope(
        "parental",
        {"adult": {"mode": "blocked"}},
        {"bad.example.com": {"mode": "window", "windows": [["00:00", "23:59"]]}},
    )
    # La catégorie dit 'blocked' mais la règle de domaine autorise ici.
    d = engine.decide("bad.example.com")
    assert d.blocked is False
    assert d.rule_key == "dom:bad.example.com"
    assert d.mode == "window"


def test_rules_window_normal_range(tmp_path):
    """Mode 'window' : autorisé dans la plage, bloqué hors plage."""
    engine, _, clock = _make_engine(tmp_path, FakeListsManager())
    engine.set_scope_enabled("parental", True)
    engine.update_scope(
        "parental",
        {},
        {"game.example.com": {"mode": "window", "windows": [["17:00", "19:00"]]}},
    )
    clock.set(datetime(2026, 1, 5, 18, 0))
    d = engine.decide("game.example.com")
    assert d.blocked is False and "17:00" in d.reason

    clock.set(datetime(2026, 1, 5, 20, 0))
    d = engine.decide("game.example.com")
    assert d.blocked is True and d.mode == "window"


def test_rules_window_overnight(tmp_path):
    """Fenêtre traversant minuit (20:00-07:00) : 23h et 6h30 autorisés, midi bloqué."""
    engine, _, clock = _make_engine(tmp_path, FakeListsManager())
    engine.set_scope_enabled("domestic", True)
    engine.update_scope(
        "domestic",
        {},
        {"tv.example.local": {"mode": "window", "windows": [["20:00", "07:00"]]}},
    )
    clock.set(datetime(2026, 1, 5, 23, 0))
    assert engine.decide("tv.example.local").blocked is False
    clock.set(datetime(2026, 1, 6, 6, 30))
    assert engine.decide("tv.example.local").blocked is False
    clock.set(datetime(2026, 1, 6, 7, 0))  # borne inclusive
    assert engine.decide("tv.example.local").blocked is False
    clock.set(datetime(2026, 1, 6, 12, 0))
    d = engine.decide("tv.example.local")
    assert d.blocked is True and d.scope == "domestic"


def test_rules_quota_mode(tmp_path):
    """Mode 'quota' : autorisé tant que used < quota_minutes, bloqué ensuite."""
    engine, quota, clock = _make_engine(tmp_path, FakeListsManager())
    engine.set_scope_enabled("parental", True)
    engine.update_scope(
        "parental",
        {},
        {"video.example.com": {"mode": "quota", "quota_minutes": 2}},
    )
    d = engine.decide("video.example.com")
    assert d.blocked is False                       # used 0 -> compte la minute
    assert quota.used_minutes("dom:video.example.com") == 1

    clock.advance(minutes=1)
    d = engine.decide("video.example.com")
    assert d.blocked is False                       # used 1 -> 2, dernier crédit
    assert quota.used_minutes("dom:video.example.com") == 2

    clock.advance(minutes=1)
    d = engine.decide("video.example.com")
    assert d.blocked is True and d.mode == "quota"
    assert "quota" in d.reason
    # Un blocage ne consomme pas de minute supplémentaire
    assert quota.used_minutes("dom:video.example.com") == 2


def test_rules_update_scope_validation(tmp_path):
    """update_scope rejette modes invalides, quota sans minutes, fenêtres malformées."""
    engine, _, _ = _make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.update_scope("inconnu", {}, {})
    with pytest.raises(ValueError):
        engine.update_scope("parental", {"adult": {"mode": "nope"}}, {})
    with pytest.raises(ValueError):
        engine.update_scope("parental", {"adult": "blocked"}, {})  # non-dict
    with pytest.raises(ValueError):
        engine.update_scope("parental", {}, {"x.com": {"mode": "quota"}})  # pas de quota_minutes
    with pytest.raises(ValueError):
        engine.update_scope("parental", {}, {"x.com": {"mode": "window", "windows": [["25:00", "26:00"]]}})
    with pytest.raises(ValueError):
        engine.update_scope("parental", {}, {"x.com": {"mode": "window", "windows": [["17:00"]]}})

    # Mise à jour valide -> succès
    engine.update_scope(
        "domestic", {"payment": {"mode": "blocked"}},
        {"cam.local": {"mode": "window", "windows": [["08:00", "20:00"]]}},
    )
    rules = engine.get_rules()["domestic"]
    assert rules["categories"]["payment"]["mode"] == "blocked"
    assert rules["domains"]["cam.local"]["windows"] == [["08:00", "20:00"]]


def test_rules_scope_enabled_validation_and_persistence(tmp_path):
    """set_scope_enabled : scope inconnu -> ValueError ; état persisté sur disque."""
    engine, _, _ = _make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.set_scope_enabled("inconnu", True)

    engine.set_scope_enabled("parental", True)
    assert engine.is_enabled("parental") is True
    assert engine.is_enabled("domestic") is False
    assert (tmp_path / "parental_rules.json").is_file()

    # "Redémarrage" : nouvel engine sur le même state_dir recharge l'état
    engine2, _, _ = _make_engine(tmp_path)
    assert engine2.is_enabled("parental") is True


def test_rules_quota_status(tmp_path):
    """quota_status expose used/quota des règles quota des scopes actifs."""
    engine, quota, clock = _make_engine(tmp_path, FakeListsManager())
    engine.set_scope_enabled("parental", True)
    engine.update_scope(
        "parental",
        {"social": {"mode": "quota", "quota_minutes": 60}},
        {"vid.com": {"mode": "quota", "quota_minutes": 10}},
    )
    engine.decide("vid.com")  # consomme 1 minute
    st = engine.quota_status()
    assert st["cat:social"] == {"used": 0, "quota": 60}
    assert st["dom:vid.com"] == {"used": 1, "quota": 10}


def test_rules_cross_scope_most_restrictive(tmp_path):
    """CONTRAT DOCUMENTÉ : un domaine couvert par les deux scopes applique la
    règle la plus restrictive (blocked > window-denied > quota-exceeded > allow).

    parental autorise (fenêtre active) mais domestic bloque -> doit être bloqué.
    """
    engine, _, clock = _make_engine(tmp_path, FakeListsManager(),
                                    now=datetime(2026, 1, 5, 12, 0))
    engine.set_scope_enabled("parental", True)
    engine.set_scope_enabled("domestic", True)
    engine.update_scope(
        "parental", {},
        {"device.local": {"mode": "window", "windows": [["00:00", "23:59"]]}},
    )
    engine.update_scope(
        "domestic", {}, {"device.local": {"mode": "blocked"}}
    )
    d = engine.decide("device.local")
    assert d.blocked is True, (
        "docstring RulesEngine : la règle la plus restrictive doit gagner "
        "(domestic 'blocked' ignoré car parental matche en premier)"
    )
    assert d.scope == "domestic"


# ============================ DnsSinkhole.rule_resolver ============================


def _sinkhole(**kwargs):
    from tracker_filter.dns_sinkhole import DnsSinkhole

    return DnsSinkhole(**kwargs)


def test_sinkhole_rule_resolver_blocks_unlisted_domain():
    """Une décision blocked=True sinkhole un domaine absent des listes trackers."""
    resolver_calls = []

    def resolver(domain):
        resolver_calls.append(domain)
        return Decision(
            blocked=True, scope="parental", matched="tiktok.example.com",
            rule_key="dom:tiktok.example.com", mode="blocked",
            reason="domaine bloqué en permanence",
        )

    sink = _sinkhole(domaines=set(), rule_resolver=resolver)
    w = DummyWinDivert()
    sink._handle_packet(w, DummyPacket(_dns_query("www.tiktok.example.com")))

    assert resolver_calls == ["www.tiktok.example.com"]
    assert sink.stats["blocked_total"] == 1
    # La réponse forgée pointe vers 0.0.0.0 (sinkhole effectif)
    assert w.sent[0].payload[-4:] == socket.inet_aton("0.0.0.0")
    assert w.sent[0].dst_port == 54321  # ports inversés vers le client


def test_sinkhole_rule_resolver_enriches_blocked_detail():
    """blocked_detail porte scope/rule_key/reason issus de la Decision."""
    sink = _sinkhole(
        domaines=set(),
        rule_resolver=lambda d: Decision(
            blocked=True, scope="domestic", matched="cam.local",
            rule_key="dom:cam.local", mode="window",
            reason="hors fenêtre horaire autorisée",
        ),
    )
    w = DummyWinDivert()
    sink._handle_packet(w, DummyPacket(_dns_query("cam.local")))

    detail = sink.stats["blocked_detail"]["cam.local"]
    assert detail["scope"] == "domestic"
    assert detail["rule"] == "dom:cam.local"
    assert detail["reason"] == "hors fenêtre horaire autorisée"
    assert detail["matched_domain"] == "cam.local"


def test_sinkhole_rule_resolver_bypasses_tracker_whitelist():
    """La whitelist du filtre tracker ne s'applique PAS aux règles parentales."""
    sink = _sinkhole(
        domaines=set(),
        whitelist={"kid-game.example.com"},
        rule_resolver=lambda d: Decision(
            blocked=True, scope="parental", matched="kid-game.example.com",
            rule_key="dom:kid-game.example.com", mode="blocked", reason="bloqué",
        ),
    )
    w = DummyWinDivert()
    sink._handle_packet(w, DummyPacket(_dns_query("kid-game.example.com")))
    assert sink.stats["blocked_total"] == 1  # bloqué malgré la whitelist


def test_sinkhole_rule_resolver_allow_falls_back_to_lists():
    """Decision allow -> le filtre tracker normal reprend la main."""
    sink = _sinkhole(
        domaines={"ads.example.com"},
        whitelist={"free.example.com"},
        rule_resolver=lambda d: Decision(blocked=False),
    )
    w = DummyWinDivert()

    # allow du résolveur + présent dans domaines -> bloqué par le filtre tracker
    q = _dns_query("ads.example.com")
    sink._handle_packet(w, DummyPacket(q))
    assert sink.stats["blocked_total"] == 1
    assert w.sent[0].payload[-4:] == socket.inet_aton("0.0.0.0")

    # allow + whitelisté -> relâché inchangé
    q2 = _dns_query("free.example.com")
    pkt = DummyPacket(q2)
    sink._handle_packet(w, pkt)
    assert w.sent[-1].payload == q2
    assert sink.stats["blocked_total"] == 1

    # allow + inconnu -> relâché
    q3 = _dns_query("clean.example.org")
    sink._handle_packet(w, DummyPacket(q3))
    assert w.sent[-1].payload == q3
    assert sink.stats["queries_total"] == 3
    assert sink.stats["blocked_total"] == 1


def test_sinkhole_rule_resolver_exception_fails_open():
    """Une exception du résolveur ne casse jamais le DNS (fail-open)."""
    def boom(domain):
        raise RuntimeError("moteur en panne")

    sink = _sinkhole(domaines={"ads.example.com"}, rule_resolver=boom)
    w = DummyWinDivert()

    # Domaine inconnu : paquet relâché tel quel malgré l'exception
    q = _dns_query("clean.example.org")
    sink._handle_packet(w, DummyPacket(q))
    assert w.sent[-1].payload == q
    assert sink.stats["blocked_total"] == 0

    # Domaine listé : le filtre tracker continue de fonctionner
    q2 = _dns_query("ads.example.com")
    sink._handle_packet(w, DummyPacket(q2))
    assert sink.stats["blocked_total"] == 1
    assert w.sent[-1].payload[-4:] == socket.inet_aton("0.0.0.0")


# ============================ CookieScanner (unitaire) ============================


def _fake_chrome_db(tmp_path, monkeypatch):
    """Fabrique une base 'Cookies' Chromium minimale sous LOCALAPPDATA factice."""
    local = tmp_path / "localappdata"
    db_dir = (
        local / "Google" / "Chrome" / "User Data" / "Default" / "Network"
    )
    db_dir.mkdir(parents=True)
    db = db_dir / "Cookies"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)")
    conn.execute("INSERT INTO cookies VALUES ('.sub.evil.example.com', 'track')")
    conn.execute("INSERT INTO cookies VALUES ('.good.example.com', 'sess')")
    conn.commit()
    conn.close()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.delenv("APPDATA", raising=False)  # pas de scan Firefox réel
    return db


def test_cookie_scanner_finds_suspect_cookies(tmp_path, monkeypatch):
    """scan() matche host_key par suffixe et remonte un Finding typé."""
    from parental_control.cookies_scanner import CookieScanner

    _fake_chrome_db(tmp_path, monkeypatch)
    scanner = CookieScanner()
    findings = scanner.scan({"evil.example.com"})

    assert len(findings) == 1
    f = findings[0]
    assert f.browser == "chrome" and f.profile == "Default"
    assert f.host_key == ".sub.evil.example.com"
    assert f.cookie_name == "track"
    assert f.matched_domain == "evil.example.com"
    assert scanner.last_status["chrome"] == "ok"


def test_cookie_scanner_purge_deletes_only_flagged(tmp_path, monkeypatch):
    """purge() supprime uniquement les cookies signalés (host+name précis)."""
    from parental_control.cookies_scanner import CookieScanner

    db = _fake_chrome_db(tmp_path, monkeypatch)
    scanner = CookieScanner()
    findings = scanner.scan({"evil.example.com"})
    report = scanner.purge(findings)

    assert report["deleted_total"] == 1
    assert report["browsers"]["chrome"]["status"] == "ok"

    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT host_key, name FROM cookies").fetchall()
    conn.close()
    assert rows == [(".good.example.com", "sess")]


# ============================ Endpoints FastAPI ============================


@pytest.fixture
def parental_env(tmp_path, monkeypatch):
    """Singletons port_dashboard isolés sur tmp_path + TestClient.

    _uvicorn_server est remplacé par un fake : /api/shutdown appelle sinon
    os._exit(0) dans un thread différé, ce qui tuerait le processus pytest.
    """
    import port_dashboard as pd
    from fastapi.testclient import TestClient

    pin = PinManager(tmp_path / "parental_pin.json")
    lists = FakeListsManager(
        {"adult": {"bad.example.com"}, "payment": {"pay.example.com"}}
    )
    quota = QuotaTracker(str(tmp_path))
    engine = RulesEngine(lists, quota, str(tmp_path))

    monkeypatch.setattr(pd, "_pin_manager", pin)
    monkeypatch.setattr(pd, "_lists_manager", lists)
    monkeypatch.setattr(pd, "_quota_tracker", quota)
    monkeypatch.setattr(pd, "_rules_engine", engine)
    monkeypatch.setattr(pd, "_sinkhole", None)

    class FakeUvicorn:
        should_exit = False

    fake_server = FakeUvicorn()
    monkeypatch.setattr(pd, "_uvicorn_server", fake_server)

    pd._parental_sessions.clear()
    client = TestClient(pd.app)
    yield client, pin, engine, lists, fake_server
    pd._parental_sessions.clear()


def _verify_session(client, pin="1234"):
    """Ouvre une session PIN via l'API et vérifie que le cookie est posé."""
    res = client.post("/api/parental/verify", json={"pin": pin})
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert client.cookies.get("cerbere_parental")
    return res


def test_api_parental_status(parental_env):
    """GET /api/parental/status : état complet, PIN non défini par défaut."""
    client, *_ = parental_env
    res = client.get("/api/parental/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["enabled"] is False
    assert data["pin_set"] is False
    assert "adult" in data["lists"]
    assert data["lists"]["adult"]["count"] == 1


def test_api_pin_set_and_verify_flow(parental_env):
    """POST /api/parental/pin puis /verify : 401 mauvais PIN, 200 + cookie bon PIN."""
    client, pin, *_ = parental_env

    # Format invalide -> 400
    assert client.post("/api/parental/pin", json={"new_pin": "12"}).status_code == 400

    # Définition initiale
    res = client.post("/api/parental/pin", json={"new_pin": "1234"})
    assert res.status_code == 200 and res.json()["success"] is True
    assert client.get("/api/parental/status").json()["pin_set"] is True

    # Mauvais PIN -> 401, pas de cookie
    res = client.post("/api/parental/verify", json={"pin": "0000"})
    assert res.status_code == 401
    assert not client.cookies.get("cerbere_parental")

    _verify_session(client)


def test_api_pin_change_via_endpoint(parental_env):
    """PIN déjà défini : /api/parental/pin devient un change (old_pin requis)."""
    client, *_ = parental_env
    client.post("/api/parental/pin", json={"new_pin": "1234"})

    # Mauvais ancien PIN -> 403
    res = client.post(
        "/api/parental/pin", json={"old_pin": "9999", "new_pin": "5678"}
    )
    assert res.status_code == 403

    # Bon ancien PIN -> succès, le nouveau est actif
    res = client.post(
        "/api/parental/pin", json={"old_pin": "1234", "new_pin": "5678"}
    )
    assert res.status_code == 200
    _verify_session(client, pin="5678")


def test_api_parental_toggle_requires_pin_session(parental_env):
    """toggle : 403 sans session PIN, 200 après verify ; enabled reflété."""
    client, _, engine, *_ = parental_env

    res = client.post("/api/parental/toggle", json={"enabled": True})
    assert res.status_code == 403

    client.post("/api/parental/pin", json={"new_pin": "1234"})
    _verify_session(client)

    res = client.post("/api/parental/toggle", json={"enabled": True})
    assert res.status_code == 200 and res.json()["enabled"] is True
    assert engine.is_enabled("parental") is True
    assert client.get("/api/parental/status").json()["enabled"] is True

    res = client.post("/api/parental/toggle", json={"enabled": False})
    assert res.status_code == 200
    assert engine.is_enabled("parental") is False


def test_api_parental_rules_put_validation(parental_env):
    """PUT /api/parental/rules : 403 sans session, 400 règles invalides, 200 ok."""
    client, *_ = parental_env

    res = client.put("/api/parental/rules", json={"categories": {}, "domains": {}})
    assert res.status_code == 403

    client.post("/api/parental/pin", json={"new_pin": "1234"})
    _verify_session(client)

    assert client.put(
        "/api/parental/rules", json={"categories": {"adult": {"mode": "x"}}}
    ).status_code == 400
    assert client.put(
        "/api/parental/rules", json={"domains": {"a.com": {"mode": "quota"}}}
    ).status_code == 400

    res = client.put("/api/parental/rules", json={
        "categories": {"adult": {"mode": "blocked"}},
        "domains": {"game.com": {"mode": "window",
                                "windows": [["17:00", "19:00"]]}},
    })
    assert res.status_code == 200

    rules = client.get("/api/parental/rules").json()
    assert rules["categories"]["adult"]["mode"] == "blocked"
    assert rules["domains"]["game.com"]["windows"] == [["17:00", "19:00"]]


def test_api_domestic_mirrors(parental_env):
    """Endpoints /api/domestic/* : statut, toggle PIN-guardé, rules."""
    client, _, engine, *_ = parental_env

    res = client.get("/api/domestic/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["cookies_available"] is True  # CookieScanner importable
    assert data["enabled"] is False

    # toggle guardé par la session PIN
    assert client.post(
        "/api/domestic/toggle", json={"enabled": True}
    ).status_code == 403
    client.post("/api/parental/pin", json={"new_pin": "1234"})
    _verify_session(client)
    res = client.post("/api/domestic/toggle", json={"enabled": True})
    assert res.status_code == 200
    assert engine.is_enabled("domestic") is True

    # rules domestic (même session PIN)
    res = client.put("/api/domestic/rules", json={
        "categories": {"payment": {"mode": "blocked"}}, "domains": {},
    })
    assert res.status_code == 200
    rules = client.get("/api/domestic/rules").json()
    assert rules["categories"]["payment"]["mode"] == "blocked"


def test_api_blocked_journals_filtered_by_scope(parental_env, monkeypatch):
    """/api/parental/blocked et /api/domestic/blocked filtrent le journal par scope."""
    import port_dashboard as pd

    client, *_ = parental_env

    class MockSinkhole:
        stats = {
            "blocked_detail": {
                "bad.example.com": {"count": 2, "matched_domain": "bad.example.com",
                                     "scope": "parental", "rule": "cat:adult",
                                     "reason": "domaine bloqué en permanence"},
                "pay.example.com": {"count": 1, "matched_domain": "pay.example.com",
                                     "scope": "domestic", "rule": "cat:payment",
                                     "reason": "domaine bloqué en permanence"},
                "ads.tracker.com": {"count": 5, "matched_domain": "tracker.com",
                                     "sources": ["easylist"], "rule": "||tracker.com^"},
            }
        }

    monkeypatch.setattr(pd, "_sinkhole", MockSinkhole())

    items_p = client.get("/api/parental/blocked").json()["items"]
    assert [i["domain"] for i in items_p] == ["bad.example.com"]
    assert items_p[0]["scope"] == "parental"

    items_d = client.get("/api/domestic/blocked").json()["items"]
    assert [i["domain"] for i in items_d] == ["pay.example.com"]

    # Le blocage tracker (sans scope) n'apparaît dans aucun des deux journaux


def test_api_cookies_scan_returns_findings_list(parental_env, monkeypatch):
    """POST /api/domestic/cookies/scan -> 200 + liste (scanner disponible)."""
    import port_dashboard as pd

    client, *_ = parental_env
    # Listes vides -> aucun domaine suspect -> scan immédiat, déterministe,
    # sans toucher aux vraies bases de cookies de la machine.
    monkeypatch.setattr(pd, "_lists_manager", FakeListsManager({}))

    res = client.post("/api/domestic/cookies/scan")
    assert res.status_code == 200
    assert res.json()["findings"] == []


def test_api_cookies_scan_501_if_scanner_unavailable(parental_env, monkeypatch):
    """Le scan remonte 501 uniquement si CookieScanner est indisponible."""
    import port_dashboard as pd

    client, *_ = parental_env
    monkeypatch.setattr(pd, "_cookie_scanner", None)
    monkeypatch.setattr(pd, "CookieScanner", None)
    res = client.post("/api/domestic/cookies/scan")
    assert res.status_code == 501


def test_api_cookies_purge_requires_pin(parental_env, monkeypatch):
    """Purge : 403 sans session PIN ; 200 + rapport après verify."""
    import port_dashboard as pd

    client, *_ = parental_env
    assert client.post(
        "/api/domestic/cookies/purge", json={"findings": []}
    ).status_code == 403

    client.post("/api/parental/pin", json={"new_pin": "1234"})
    _verify_session(client)
    res = client.post("/api/domestic/cookies/purge", json={"findings": []})
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert res.json()["report"]["deleted_total"] == 0


def test_api_shutdown_forbidden_when_protection_active(parental_env):
    """Protection active + pas de PIN -> 403 ; mauvais PIN en corps -> 403."""
    client, pin, engine, _, server = parental_env
    pin.set_pin("1234")
    engine.set_scope_enabled("parental", True)

    assert client.post("/api/shutdown").status_code == 403
    assert client.post("/api/shutdown", json={"pin": "0000"}).status_code == 403
    assert server.should_exit is False


def test_api_shutdown_ok_with_pin_in_body(parental_env):
    """Le systray peut passer le PIN en corps JSON : arrêt accepté (200)."""
    client, pin, engine, _, server = parental_env
    pin.set_pin("1234")
    engine.set_scope_enabled("domestic", True)

    res = client.post("/api/shutdown", json={"pin": "1234"})
    assert res.status_code == 200 and res.json()["success"] is True
    time.sleep(1.0)  # thread différé (0.6 s)
    assert server.should_exit is True


def test_api_shutdown_ok_with_pin_session_cookie(parental_env):
    """Une session PIN valide (cookie) autorise aussi l'arrêt complet."""
    client, pin, engine, _, server = parental_env
    pin.set_pin("1234")
    engine.set_scope_enabled("parental", True)
    _verify_session(client)

    res = client.post("/api/shutdown")
    assert res.status_code == 200
    time.sleep(1.0)
    assert server.should_exit is True


def test_api_shutdown_free_when_protection_disabled(parental_env):
    """Protection inactive -> /api/shutdown ne demande aucun PIN."""
    client, *_rest, server = parental_env
    res = client.post("/api/shutdown")
    assert res.status_code == 200
    time.sleep(1.0)
    assert server.should_exit is True
