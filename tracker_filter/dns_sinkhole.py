"""Sinkhole DNS basé sur WinDivert pour neutraliser les trackers publicitaires.

Intercepte les requêtes DNS UDP/TCP sur le port 53, analyse les questions posées
et répond immédiatement par 0.0.0.0 pour les domaines listés dans la base de blocage.
"""

from collections import Counter
import logging
import os
import socket
import struct
import threading
import time
from typing import Callable, Dict, Optional, Set

import pydivert

logger = logging.getLogger("tracker_filter.dns_sinkhole")


class DnsSinkhole:
    """Intercepteur et puits DNS (sinkhole) via le pilote WinDivert.

    Attributs:
        domaines (Set[str]): Noms de domaine à neutraliser (en minuscules).
        whitelist (Set[str]): Domaines autorisés à ignorer lors du blocage.
        alert_callback (Optional[Callable[[int, str], None]]): Fonction de notification d'alerte.
        domain_meta (Dict[str, dict]): Métadonnées des règles indexées par domaine.
        running (bool): Indique si la boucle d'interception est active.
        stats (dict): Compteurs de requêtes, blocages, détails et statistiques par domaine.
    """

    def __init__(
        self,
        domaines: Set[str],
        whitelist: Optional[Set[str]] = None,
        alert_callback: Optional[Callable[[int, str], None]] = None,
        domain_meta: Optional[Dict[str, dict]] = None,
        notify_grace_seconds: float = 60.0,
        state_dir: Optional[str] = None,
        rule_resolver: Optional[Callable[[str], object]] = None,
    ):
        """Initialise le sinkhole avec les listes de domaines et options.

        Args:
            domaines: Ensemble des domaines à bloquer.
            whitelist: Ensemble optionnel de domaines à ne jamais bloquer.
            alert_callback: Fonction recevant (score: int, message: str) lors d'un blocage inédit.
            domain_meta: Dictionnaire optionnel associant domaine à {'sources': [...], 'rule': '...'}.
            rule_resolver: Fonction optionnelle `(domain) -> Decision` (moteur
                parental/domestique). Si elle renvoie une décision ``blocked``,
                le domaine est sinkholé même s'il n'est pas dans ``domaines`` ;
                la whitelist du filtre tracker ne s'applique pas à ces règles.
        """
        self.rule_resolver = rule_resolver
        self.domaines: Set[str] = {d.lower() for d in domaines} if domaines else set()
        self.whitelist: Set[str] = {w.lower() for w in whitelist} if whitelist else set()
        self.alert_callback = alert_callback
        self.domain_meta: Dict[str, dict] = domain_meta or {}
        # Grace au démarrage : les domaines bloqués pendant cette fenêtre sont
        # comptabilisés et marqués comme connus, mais ne déclenchent pas
        # l'alerte Windows (évite la tempête de notifications au 1er lancement).
        self.notify_grace_seconds: float = notify_grace_seconds
        self._started_at: float = 0.0

        self.running: bool = False
        self.initialization_error: Optional[str] = None
        self.stats = {
            "blocked_total": 0,
            "blocked_domains": Counter(),
            "blocked_detail": {},
            "queries_total": 0,
        }

        # Persistance des domaines deja notifies : evite la rafale de
        # notifications Windows a chaque redemarrage du backend.
        self._state_dir = state_dir
        self._notified_file = (
            os.path.join(state_dir, "notified_domains.json") if state_dir else None
        )
        self._notified: Set[str] = self._load_notified()
        self._thread: Optional[threading.Thread] = None
        self._divert: Optional[pydivert.WinDivert] = None
        self._lock = threading.Lock()

    def _load_notified(self) -> Set[str]:
        """Recharge les domaines deja notifies depuis le disque."""
        if not self._notified_file or not os.path.isfile(self._notified_file):
            return set()
        try:
            import json as _json
            data = _json.loads(open(self._notified_file, "r", encoding="utf-8").read() or "[]")
            return {str(d).lower() for d in data if isinstance(d, str)}
        except Exception as e:
            logger.debug("Impossible de charger notified_domains.json: %s", e)
            return set()

    def _save_notified(self) -> None:
        """Persiste l'ensemble des domaines notifies (ecriture atomique)."""
        if not self._notified_file:
            return
        try:
            import json as _json
            os.makedirs(os.path.dirname(self._notified_file), exist_ok=True)
            tmp = self._notified_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(sorted(self._notified), f)
            os.replace(tmp, self._notified_file)
        except Exception as e:
            logger.debug("Impossible de sauvegarder notified_domains.json: %s", e)

    def start(self) -> None:
        """Démarre le thread d'écoute daemon avec WinDivert."""
        with self._lock:
            if self.running:
                return
            self.initialization_error = None
            self.running = True
            self._started_at = time.monotonic()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="DnsSinkholeWorker",
                daemon=True,
            )
            self._thread.start()
            logger.info("DnsSinkhole démarré avec %d domaines bloqués.", len(self.domaines))

    def stop(self) -> None:
        """Arrête proprement l'intercepteur et ferme le handle WinDivert."""
        with self._lock:
            if not self.running:
                return
            self.running = False

            if self._divert is not None:
                try:
                    self._divert.close()
                except Exception as e:
                    logger.debug("Erreur à la fermeture du handle WinDivert: %s", e)

            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self._thread = None
            self._divert = None
            logger.info("DnsSinkhole arrêté proprement.")

    def _run_loop(self) -> None:
        """Boucle principale de capture des paquets DNS via WinDivert."""
        filter_str = "udp.DstPort == 53 or tcp.DstPort == 53"
        try:
            with pydivert.WinDivert(filter_str) as w:
                self._divert = w
                while self.running:
                    try:
                        packet = w.recv()
                    except Exception as recv_err:
                        if not self.running:
                            break
                        logger.warning("Erreur réception paquet WinDivert: %s", recv_err)
                        continue

                    try:
                        self._handle_packet(w, packet)
                    except Exception as proc_err:
                        # Règle FAIL-OPEN absolue : jamais de drop implicite sur exception
                        logger.error("Exception non gérée dans le traitement: %s", proc_err)
                        try:
                            w.send(packet)
                        except Exception:
                            pass
        except Exception as init_err:
            self.initialization_error = str(init_err)
            logger.error("Impossible d'initialiser WinDivert (privilèges requis ?): %s", init_err)
        finally:
            self.running = False
            self._divert = None

    def _handle_packet(self, w: pydivert.WinDivert, packet: pydivert.Packet) -> None:
        """Traite un paquet réseau et répond avec une fausse réponse DNS si bloqué."""
        # FAIL-OPEN TCP : Si le protocole est TCP, relâcher immédiatement
        if not getattr(packet, "is_udp", False) and not (packet.protocol == 17 or getattr(packet, "udp", None)):
            w.send(packet)
            return

        payload = packet.payload
        if not payload or len(payload) < 12:
            w.send(packet)
            return

        txid, domain, qsection = self._parse_dns_query(payload)
        if not domain or not qsection:
            # Erreur parsing ou pas de question DNS valide -> fail-open
            w.send(packet)
            return

        self.stats["queries_total"] += 1

        # Évaluation des règles parentales/domestiques (prioritaires, hors
        # whitelist du filtre tracker : une catégorie « interdit » ne doit pas
        # être contournée par la whitelist publicité).
        decision = None
        if self.rule_resolver is not None:
            try:
                decision = self.rule_resolver(domain)
            except Exception as e:
                # FAIL-OPEN : une erreur du moteur ne doit pas casser le DNS
                logger.error("Erreur rule_resolver pour %s: %s", domain, e)

        if decision is not None and getattr(decision, "blocked", False):
            matched_domain = getattr(decision, "matched", "") or domain
        else:
            # Vérification du domaine et de ses suffixes parents (filtre tracker)
            matched_domain = self._match(domain)
        if not matched_domain:
            w.send(packet)
            return

        # Domaine bloqué : mise à jour des statistiques
        self.stats["blocked_total"] += 1
        self.stats["blocked_domains"][domain] += 1
        logger.debug(
            "Requête bloquée : %s (règle=%s)", domain, matched_domain
        )

        # Enregistrement détaillé du blocage (lookup O(1))
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        if domain not in self.stats["blocked_detail"]:
            meta = self.domain_meta.get(matched_domain) or self.domain_meta.get(domain) or {}
            detail_new = {
                "count": 1,
                "matched_domain": matched_domain,
                "sources": list(meta.get("sources", [])),
                "rule": meta.get("rule", ""),
                "first_seen": now_iso,
                "last_seen": now_iso,
            }
            if decision is not None and getattr(decision, "blocked", False):
                detail_new["scope"] = getattr(decision, "scope", "")
                detail_new["rule"] = getattr(decision, "rule_key", "") or detail_new["rule"]
                detail_new["reason"] = getattr(decision, "reason", "")
            self.stats["blocked_detail"][domain] = detail_new
        else:
            detail = self.stats["blocked_detail"][domain]
            detail["count"] += 1
            detail["last_seen"] = now_iso

        # Déclenchement alerte unique par nouveau domaine (silencieux en grace,
        # dédoublonné de façon persistante entre redémarrages)
        if self.alert_callback and domain not in self._notified:
            self._notified.add(domain)
            self._save_notified()
            if time.monotonic() - self._started_at >= self.notify_grace_seconds:
                logger.info("Notification nouveau domaine bloqué : %s", domain)
                scope = getattr(decision, "scope", "") if decision else ""
                if scope == "parental":
                    msg = f"Contrôle parental : {domain} bloqué"
                elif scope == "domestic":
                    msg = f"Contrôle domestique : {domain} bloqué"
                else:
                    msg = f"Tracker/ad DNS bloqué: {domain}"
                try:
                    self.alert_callback(50, msg)
                except Exception as cb_err:
                    logger.error("Erreur exécution alert_callback: %s", cb_err)
            else:
                logger.debug("Domaine %s bloqué pendant la période de grâce (pas de notification)", domain)

        # Forge de la réponse DNS menteuse (sinkhole 0.0.0.0)
        forged_dns_payload = self._build_sinkhole_response(txid, qsection)

        # Inversion des adresses et ports UDP
        packet.src_addr, packet.dst_addr = packet.dst_addr, packet.src_addr
        packet.src_port, packet.dst_port = packet.dst_port, packet.src_port
        packet.direction = pydivert.Direction.INBOUND
        packet.payload = forged_dns_payload

        if hasattr(packet, "recalculate_checksums"):
            packet.recalculate_checksums()

        w.send(packet)

    def _match(self, domain: str) -> Optional[str]:
        """Vérifie si le domaine ou l'un de ses suffixes parents correspond aux listes de blocage.

        Returns:
            Le candidat (suffixe parent ou domaine) ayant matché dans self.domaines,
            ou None si le domaine n'est pas bloqué ou est en whitelist.
        """
        parts = domain.split(".")
        if len(parts) <= 1:
            candidates = [domain]
        else:
            candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]

        # Vérification préalable de la whitelist (prioritaire sur le blocage)
        if any(c in self.whitelist for c in candidates):
            return None

        # Recherche du candidat ayant matché dans les listes de blocage
        for c in candidates:
            if c in self.domaines:
                return c

        return None

    def _is_blocked(self, domain: str) -> bool:
        """Vérifie si le domaine ou l'un de ses suffixes parents correspond aux listes de blocage."""
        return self._match(domain) is not None

    @staticmethod
    def _parse_dns_query(payload: bytes):
        """Parse manuellement la section Header et Question du paquet DNS.

        Returns:
            Tuple (txid, domain, qsection_bytes) ou (None, None, None) si échec.
        """
        try:
            txid = payload[:2]
            flags, qdcount = struct.unpack("!HH", payload[2:6])
            if qdcount < 1:
                return None, None, None

            idx = 12
            labels = []
            while idx < len(payload):
                length = payload[idx]
                if length == 0:
                    idx += 1
                    break
                if (length & 0xC0) != 0:
                    # Pointeur de compression inattendu dans la question
                    return None, None, None
                idx += 1
                if idx + length > len(payload):
                    return None, None, None
                # Filtre les caracteres de controle (\r\n...) pour eviter
                # l'injection de texte dans les notifications et les logs.
                raw_label = payload[idx : idx + length].decode("ascii", errors="ignore")
                labels.append("".join(c for c in raw_label if c.isalnum() or c in "-_"))
                idx += length

            if idx + 4 > len(payload):
                return None, None, None

            # QTYPE (2B) + QCLASS (2B)
            qsection_bytes = payload[12 : idx + 4]
            domain = ".".join(labels).lower()
            return txid, domain, qsection_bytes
        except Exception:
            return None, None, None

    @staticmethod
    def _build_sinkhole_response(txid: bytes, qsection: bytes) -> bytes:
        """Construit une réponse DNS A pointant vers 0.0.0.0.

        Flags 0x8180 : Réponse standard sans erreur, récursion acceptée.
        Réponse RR : Pointeur 0xC00C, Type A (1), Classe IN (1), TTL 60s, RDATA 0.0.0.0.
        """
        # Header DNS : 1 question, 1 réponse, 0 autorité, 0 additionnel
        header = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)

        # RR Réponse A pointant vers 0.0.0.0
        # Pointeur 0xC00C (offset 12 pointant sur QNAME de la section question)
        answer_rr = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton("0.0.0.0")
        )

        return header + qsection + answer_rr
