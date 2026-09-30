"""Notifications externes pour Cerbere Security Shield (T43).

Envoie les alertes critiques vers un canal externe :
- Webhook HTTP POST (Pushover, n8n, IFTTT, etc.) — recommande
- Email via SMTP (option avancee)

Concu pour etre appele dans un thread daemon : non bloquant et fail-open
(aucune exception n'est propagee vers le pipeline d'alertes).
"""

from __future__ import annotations

import json
import smtplib
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Dict


def send_external_alert(cfg: Dict[str, Any], score: int, message: str) -> bool:
    """Envoie une alerte vers le(s) canal(aux) externe(s) configure(s).

    Args:
        cfg: Configuration courante (webhook_url, alert_email, smtp_*,
             external_min_severity).
        score: Score de severite de l'alerte (0-100).
        message: Texte de l'alerte.

    Returns:
        True si au moins un envoi a reussi, False sinon.
    """
    try:
        min_sev = int(cfg.get("external_min_severity", 90))
    except Exception:
        min_sev = 90
    if score < min_sev:
        return False

    timestamp = datetime.now().isoformat(timespec="seconds")
    sent = False

    webhook_url = str(cfg.get("webhook_url") or "").strip()
    if webhook_url:
        try:
            payload = json.dumps({
                "app": "Cerbere Security Shield",
                "score": score,
                "message": message,
                "timestamp": timestamp,
            }).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                sent = 200 <= resp.status < 300
        except Exception:
            pass

    alert_email = str(cfg.get("alert_email") or "").strip()
    smtp_host = str(cfg.get("smtp_host") or "").strip()
    if alert_email and smtp_host:
        try:
            msg = EmailMessage()
            msg["From"] = str(cfg.get("smtp_user") or "cerbere@localhost")
            msg["To"] = alert_email
            msg["Subject"] = f"Cerbere Security Shield — Alerte ({score}/100)"
            msg.set_content(
                f"Alerte de securite detectee par Cerbere Security Shield\n\n"
                f"Date : {timestamp}\nScore : {score}/100\n\n{message}\n"
            )
            port = int(cfg.get("smtp_port") or 465)
            user = str(cfg.get("smtp_user") or "")
            password = str(cfg.get("smtp_password") or "")
            if port == 465:
                smtp = smtplib.SMTP_SSL(smtp_host, port, timeout=10)
            else:
                smtp = smtplib.SMTP(smtp_host, port, timeout=10)
                smtp.starttls()
            with smtp:
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)
            sent = True
        except Exception:
            pass

    return sent
