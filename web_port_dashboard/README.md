# Cerbere Security Shield — Web Port Dashboard

Sous-répertoire dédié au composant dashboard et surveillance des ports de Cerbere Security Shield avec interface web locale.

- PRD de référence : `prd/prd-web-port-dashboard.md`
- Objectif : script Python autonome + petite API HTTP locale + page web de visualisation.

## Installation des dépendances

- Depuis la racine du projet `security_sheeld` :

```bash
pip install -r requirements.txt
```

Le fichier `requirements.txt` inclut notamment FastAPI, Uvicorn, psutil et PyYAML.

## Configuration

Ordre de recherche de la configuration au démarrage du service :

1. `web_port_dashboard/config.yml` (config spécifique au dashboard)
2. `security_audit/config.yml` (config globale partagée si présente)
3. Configuration par défaut en dur (si aucun fichier n’est trouvé ou en cas d’erreur de parsing)

Clés supportées pour le dashboard :

- `debug` : booléen
- `critical_ports` : liste de numéros de ports critiques
- `allowed_ports` : liste d’objets ports autorisés (même style que `config.example.yml`)
- `scan_interval_seconds` : intervalle entre deux scans (en secondes)

Exemple minimal de `web_port_dashboard/config.yml` :

```yaml
debug: false
critical_ports:
  - 22
  - 80
  - 443
scan_interval_seconds: 10
```

## Lancement du service (mode développement)

Depuis la racine du projet `security_sheeld` :

```bash
python -m web_port_dashboard.port_dashboard
```

Le serveur démarre sur `http://127.0.0.1:4050`.

- Endpoint JSON principal : `GET /api/ports/current`
  - Retourne le dernier snapshot de ports scannés et le score de risque global.

La page HTML du dashboard est servie à la racine : `GET /` → `static/index.html`.

## Lancement en service Windows (production locale)

Un service Windows « WebPortDashboard » peut être créé avec **NSSM** pour démarrer automatiquement le serveur FastAPI au boot.

- Commande de base (exécutée une fois en PowerShell admin, depuis n’importe où) :

```powershell
nssm install WebPortDashboard `
    "python.exe" `
    "-m" "uvicorn" "web_port_dashboard.port_dashboard:app" "--host" "127.0.0.1" "--port" "4050"

nssm set WebPortDashboard AppDirectory "F:\\Promgramation-teste\\security_sheeld"
nssm set WebPortDashboard Start SERVICE_AUTO_START
nssm start WebPortDashboard
```

Une fois le service démarré, l’interface est disponible sur `http://127.0.0.1:4050/`.

## Endpoints FastAPI principaux

- `GET /api/ports/current`  
  Dernier snapshot des ports, niveaux de risque, score global.

- `GET /api/protection/state` / `POST /api/protection/state`  
  État global de protection (activée/désactivée) persistant dans `web_port_dashboard/state/protection_state.json`.

- `GET /api/config/selection` / `POST /api/config/selection`  
  Configuration de sélection de ports côté backend, stockée dans `web_port_dashboard/state/selection_config.json`.  
  Utilisée par la WebUI pour restaurer les cases cochées.

## Systray Windows (client C#)

Une petite application systray C#/.NET se trouve dans le dossier `systray_client/` :

- Projet : `systray_client/WebPortSystray.csproj` (WinForms, .NET 6.0 Windows).
- Fichiers principaux :
  - `Program.cs` : point d’entrée.
  - `TrayApplication.cs` : logique de l’icône de notification et du menu.

Fonctionnalités :

- Icône dans la zone de notification Windows affichant l’état de protection :
  - ACTIVÉE / DÉSACTIVÉE / serveur indisponible.
- Menu contextuel (clic droit) :
  - Ouvrir Cerbere Security Shield.
  - Activer la protection (POST `/api/protection/state` avec `enabled=true`).
  - Désactiver la protection (POST `/api/protection/state` avec `enabled=false`).
  - Quitter l’application systray.

Build et exécution manuelle :

```powershell
cd F:\Promgramation-teste\security_sheeld\systray_client
dotnet build -c Release
dotnet run
```

## Auto-démarrage de la systray à l’ouverture de session

Un script d’aide est fourni dans `systray_client/install_systray_autorun.ps1` pour enregistrer/désenregistrer l’application systray dans la clé de registre :

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

Usage (PowerShell) :

```powershell
cd F:\Promgramation-teste\security_sheeld\systray_client
# Construire d’abord en Release si nécessaire
dotnet build -c Release

# Enregistrer l’auto-démarrage pour l’utilisateur courant
.\install_systray_autorun.ps1

# Supprimer l’auto-démarrage
.\install_systray_autorun.ps1 -Uninstall
```

L’application systray sera alors lancée automatiquement à chaque ouverture de session Windows, tant que le service `WebPortDashboard` est présent et démarré.
