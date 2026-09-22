## auth-first-run-audit-v092

## Audit auth first-run (v0.9.2-beta) — PASS

Déclenché après lock-out beta testeur Windows Hello (pas de mot de passe local → LogonUserW toujours KO).

Points vérifiés dans `web_port_dashboard/port_dashboard.py` :
- `first_run` = `method=='app' and not acc.get('app_password_hash')` → impossible d'écraser un hash existant via /api/unlock (l.580)
- `PUT /api/settings` couvert par middleware `_auth_guard` (préfixe `/api/settings` dans _GUARDED_PREFIXES l.480) → pas de bypass access.enabled ni reset hash sans session
- Mot de passe jamais loggué ; seul PBKDF2-HMAC-SHA256 (100k iter, sel 16o) persisté
- Cookie `cerbere_session` : httponly=True, samesite=lax (l.618)
- Méthode `windows` (LogonUserW) préservée dans le dispatch (l.597-599)
- Modèle de menace résiduel accepté : attaquant avec accès fichier local peut supprimer la config (hors périmètre beta)

Release : v0.9.2-beta publiée avec les 2 exe signés. Tag v0.9.1-beta burné par release immuable (non réutilisable).

**Type:** decision  
**Tags:** auth, audit, beta, windows-hello, release  
**Updated:** 22/09/2026
