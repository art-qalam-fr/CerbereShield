# Cerbere Security Shield — Web Port Dashboard & Systray – Guide rapide

## 1. Composants

- **Serveur Web Port**
  - Type : service Windows `WebPortDashboard` (NSSM)
  - Commande : Python 3.12
  - Travaille dans : `F:\Promgramation-teste\security_prd`
  - API : `http://127.0.0.1:4050/` et `http://127.0.0.1:4050/api/protection/state`

- **Client Systray**
  - Appli : `WebPortSystray.exe`
  - Chemin : `F:\Promgramation-teste\security_prd\systray_client\bin\Release\net6.0-windows\WebPortSystray.exe`
  - Icône dans la zone de notification Windows

---

## 2. Démarrer / arrêter le serveur (service `WebPortDashboard`)

### 2.1. Démarrer le service

En **PowerShell administrateur** :

```powershell
net start WebPortDashboard
```

- Si tout va bien : le service démarre et écoute sur `http://127.0.0.1:4050/`.
- Si erreur, voir section **4. Diagnostic**.

### 2.2. Arrêter le service

```powershell
net stop WebPortDashboard
```

---

## 3. Vérifier que tout fonctionne

### 3.1. Vérifier le serveur Web Port

Depuis le navigateur sur la machine locale :

- Accès interface : `http://127.0.0.1:4050/`
- API d’état (utilisée par la systray) :
  - `http://127.0.0.1:4050/api/protection/state`

Si la page / API ne répond pas :

- soit le service `WebPortDashboard` n’est pas démarré,
- soit il a démarré puis crashé (voir **4. Diagnostic**).

### 3.2. Vérifier / lancer la systray manuellement

En PowerShell (n’importe où) :

```powershell
& "F:\Promgramation-teste\security_prd\systray_client\bin\Release\net6.0-windows\WebPortSystray.exe"
```

- L’icône apparaît dans la zone de notification (ou dans les icônes masquées `^`).
- États possibles :
  - **"Web Port Protection - ACTIVÉE"** : serveur OK, protection activée.
  - **"Web Port Protection - DÉSACTIVÉE"** : serveur OK, protection désactivée.
  - **"Web Port Protection - serveur indisponible"** (icône "!" / Warning) :
    - le serveur `http://127.0.0.1:4050` n’est pas accessible → vérifier le service.

---

## 4. Diagnostic du service `WebPortDashboard`

### 4.1. Vérifier l’état du service

```powershell
sc query WebPortDashboard
```

- `STATE` = `RUNNING` → le service est en cours.
- `STATE` = `STOPPED` ou démarrage en erreur → voir ci‑dessous.

### 4.2. Erreur de démarrage typique

Au démarrage, si tu vois par exemple :

```text
Le service WebPortDashboard démarre.
Le service WebPortDashboard n’a pas pu être lancé.
Une erreur spécifique à un service s’est produite : 3.
```

En pratique, cela signifie généralement :

- **chemin introuvable** (mauvais Path / Arguments / Startup directory côté NSSM).

Dans ce cas, ouvrir l’interface NSSM (section 5) et vérifier :

- `Path` pointe bien vers Python 3.12.
- `Arguments` contiennent bien `-m web_port_dashboard.port_dashboard`.
- `Startup directory` est bien `F:\Promgramation-teste\security_prd`.

---

## 5. Accéder à la configuration NSSM

Le service `WebPortDashboard` est géré par **NSSM** via :

- Binaire : `C:\ProgramData\chocolatey\bin\nssm.exe`

### 5.1. Ouvrir l’interface d’édition du service

En **PowerShell administrateur** :

```powershell
& "C:\ProgramData\chocolatey\bin\nssm.exe" edit WebPortDashboard
```

Une fenêtre NSSM s’ouvre. Vérifier/ajuster :

- **Application**
  - **Path** :

    ```text
    C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe
    ```

  - **Arguments** :

    ```text
    -m web_port_dashboard.port_dashboard
    ```

  - **Startup directory** :

    ```text
    F:\Promgramation-teste\security_prd
    ```

Après modification, cliquer sur **Edit service** puis :

```powershell
net stop WebPortDashboard
net start WebPortDashboard
```

---

## 6. Auto‑démarrage de la systray

L’auto‑démarrage de `WebPortSystray.exe` est géré par un script PowerShell :

- Script : `F:\Promgramation-teste\security_prd\systray_client\install_systray_autorun.ps1`
- Il crée une clé dans :
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - Nom de la valeur : `WebPortSystray`
  - Valeur : chemin complet vers `WebPortSystray.exe`

### 6.1. (Ré)installer l’auto‑démarrage systray

En PowerShell **utilisateur** (pas forcément admin) dans `systray_client` :

```powershell
cd F:\Promgramation-teste\security_prd\systray_client
.\install_systray_autorun.ps1
```

Le script affiche quelque chose comme :

```text
Auto-démarrage configuré pour WebPortSystray : F:\...\WebPortSystray.exe
L’application systray sera lancée automatiquement à l’ouverture de session.
```

Ensuite, à la prochaine ouverture de session, la systray se lancera automatiquement **si** le service `WebPortDashboard` démarre correctement.

---

## 7. Résumé ultra‑court

1. **Démarrer/forcer le serveur** :

   ```powershell
   net start WebPortDashboard
   ```

2. **Tester dans un navigateur** :
   - `http://127.0.0.1:4050/`
3. **Vérifier la systray** :
   - Icône en bas à droite → texte **ACTIVÉE / DÉSACTIVÉE** = OK.
   - Texte **"serveur indisponible"** = vérifier le service.
4. **Modifier la config du service** :

   ```powershell
   & "C:\ProgramData\chocolatey\bin\nssm.exe" edit WebPortDashboard
   ```

5. **Installer/réinstaller l’auto‑start de la systray** :

   ```powershell
   cd F:\Promgramation-teste\security_prd\systray_client
   .\install_systray_autorun.ps1
   ```
