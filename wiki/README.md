# Cerbere Security Shield – Project Wiki

## 📖 Présentation

Cerbere Security Shield est une suite d'outils Windows autonome destinée à :

- **Surveiller en continu** l'exposition réseau (ports ouverts, processus associés).
- **Durcir automatiquement** le pare‑feu Windows selon un plan JSON.
- **Historiser** les snapshots de l'état réseau et les alertes via le **MCP SQLite gateway**.
- **Notifier** l'utilisateur via une icône **systray** et un tableau de bord web (FastAPI).

Le projet a été conçu pour être **100 % interne** (pas de Docker, n8n, etc.) afin de garantir la confidentialité et la légèreté d'installation.

---

## 🏗️ Architecture technique

```text
+-------------------+      JSON‑RPC (stdio)      +-------------------+
|  Windsurf IDE    | <-----------------------> |  Gateway (Python) |
+-------------------+                           +-------------------+
            ^                                         |
            |                                         |
            |                 +-----------------------+-------------------+
            |                 |                       |                   |
            |                 |   Child servers       |   MCP‑SQLite       |
            |                 |   (filesystem, time‑node, …)            |
            |                 +------------------------------------------+
            |                     (gestion via `config.json`)
```

- **Backend** : `web_port_dashboard/` – FastAPI (Uvicorn) qui expose les routes **/ports**, **/history**, **/alerts**.
- **Scheduler** : boucle `asyncio` interne qui exécute **runtime_collector** toutes les 5 min (configurable).
- **Historisation** : via le **gateway MCP SQLite** – tables `snapshots`, `alerts`.
- **Systray** : application C# (`systray_client/`) qui écoute l'API locale pour afficher des notifications.
- **Scripts utilitaires** : batch & PowerShell pour le durcissement, le lancement du serveur, la configuration du démarrage Windows.

---

## 📦 Installation

```bash
# 1. Cloner le dépôt (déjà présent)
cd F:/Promgramation-teste/security_sheeld

# 2. Créer un environnement virtuel Python 3.12+ et installer les dépendances
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 3. Installer les dépendances .NET pour le client systray (Visual Studio Build Tools) – optionnel si vous utilisez uniquement le dashboard.
```

> **Note** : Tous les scripts Windows (`*.bat`) sont déjà configurés avec les chemins relatifs.

---

## ▶️ Utilisation rapide

| Action | Script | Description |
| --- | --- | --- |
| Lancer l'application complète (dashboard + systray) | `start_complete_application.bat` | Démarre le serveur FastAPI sur le port **4050**, puis le client systray. **Auto-élévation UAC.** |
| Lancer l'application complète **avec détection d'intrusion** | `start_complete_application_with_intrusion.bat` | Idem + module `intrusion_detector` chargé par le backend. L'icône systray apparaît immédiatement (le `pip install` tourne en arrière-plan). |
| Démarrage invisible (démarrage Windows / clé Run) | `start_invisible.vbs` | Chaîne : clé `HKCU\...\Run` → VBS → `start_complete_application.bat` (qui s'élève via UAC). |
| Démarrer uniquement le dashboard | `start_web_port_dashboard.bat` | Accessible via <http://localhost:4050>. **Auto-élévation UAC.** |
| Appliquer le plan de durcissement (production) | `scripts\appliquer_plan_durcissement_ports.bat` | Utilise `scripts\powershell\security_hardening.ps1`. |
| Simuler le durcissement (dry‑run) | `scripts\run_port_hardening_dryrun.bat` | Aucun changement réel, uniquement un rapport. |
| Configurer le démarrage automatique sous Windows | `scripts\installer_demarrage_windows.bat` | Enregistre le script dans le registre ou via **NSSM**. |
| Générer le PDF d’audit | `scripts\python\generate_audit_pdf.py` | Rapport PDF à partir de `audit_data.json` + données API. |
| Détecteur d’intrusion (importé par le backend) | `scripts\python\intrusion_detector.py` | Surveillance Event Log Windows + bans IP automatiques. |

---

## 📂 Structure du dépôt

```text
security_sheeld/
├─ README.md                 # Ce wiki (racine) – résumé du projet
├─ requirements.txt          # Dépendances Python
├─ start_*.bat               # Scripts de lancement
├─ docs/                     # Documentation détaillée
│   ├─ AUTOMATED_SECURITY_SOLUTIONS.md
│   ├─ SECURE_DEPLOYMENT_GUIDE.md   # Procédure hardening (dry‑run, rollback)
│   ├─ prd/…                         # PRD, road‑map, exigences
│   └─ web_port_systray_guide.md
├─ scripts/                  # Utilitaires (batch, PowerShell, Python)
│   ├─ appliquer_plan_*.bat
│   ├─ run_port_hardening*.bat
│   ├─ installer_demarrage_windows.bat / creer_raccourcis_bureau.bat
│   ├─ powershell/…          # security_hardening.ps1, port_monitoring.ps1
│   └─ python/…              # intrusion_detector.py, generate_audit_pdf.py
├─ web_port_dashboard/       # FastAPI – tableau de bord
│   ├─ static/index.html
│   ├─ port_dashboard.py
│   └─ …
├─ systray_client/           # Application C# (icone barre tâches)
│   └─ Program.cs
├─ security_audit/           # Outils d’audit PDF et collecte de logs
└─ wiki/                     # **Ce répertoire** – wiki généré automatiquement
```

---

## 📚 Documentation interne

- **`SECURE_DEPLOYMENT_GUIDE.md`** : procédure pas‑à‑pas pour le durcissement, rollback, sauvegarde système.
- **`prd-internal-security-sheeld.md`** : PRD complet – objectifs, architecture, roadmap.
- **`documentation-technique.md`** : spécifications MCP gateway, protocoles, diagrammes Mermaid.
- **`web_port_systray_guide.md`** : guide d’utilisation du client systray.

---

## 🌐 Ressources externes (enrichissement)

### FastAPI – Quick‑Start (source : FastAPI docs)

- Créez un fichier `main.py` :

```python
from fastapi import FastAPI
app = FastAPI()

@app.get('/')
async def root():
    return {"message": "Cerbere Security Shield API ready"}
```

- Démarrez le serveur avec **uv** : `uv run fastapi dev main.py` (ou `uvicorn main:app --reload`).
- FastAPI génère automatiquement la **documentation interactive** (`/docs` et `/redoc`).

### Hardening PowerShell (extrait de la doc officielle)

```powershell
# Exemple de règle de blocage d'un port
New-NetFirewallRule -DisplayName "Block_Port_135" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block
```

Les scripts du projet utilisent la même logique avec un **mode DryRun** (`-WhatIf`).

---

## 🛠️ Contributions

1. Fork le dépôt.
2. Créez une branche `feature/<nom>`.
3. Ajoutez/modifiez la documentation dans `docs/` ou `wiki/`.
4. Soumettez une Pull Request détaillant les changements.

---

## ⚠️ Sécurité & bonnes pratiques

- **Ne partagez jamais** les clés API présentes dans `.env` (Brave, Firecrawl, Context7, N8N).
- Exécutez toujours le **dry‑run** avant tout durcissement réel.
- Conservez un **point de restauration** Windows (`Checkpoint‑Computer`).
- Gardez le **gateway** configuré pour écouter uniquement `127.0.0.1` – aucune liaison publique.

---

## 📂 Wiki navigation

- `[Home](/wiki/README.md)` – ce fichier (vue d'ensemble).
- `[Installation](/wiki/installation.md)` – étapes détaillées.
- `[Architecture](/wiki/architecture.md)` – diagrammes et description des flux.
- `[Hardening Guide](/wiki/hardening.md)` – procédure complète avec rollback.
- `[Developer Guide](/wiki/developer.md)` – build, tests, extensions MCP.

---
*Wiki généré automatiquement le 20‑09‑2026 par l'agent Goose.*
