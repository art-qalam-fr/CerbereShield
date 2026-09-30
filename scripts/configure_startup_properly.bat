@echo off
setlocal

REM ==========================================
REM Script de configuration complète du démarrage
REM ==========================================

REM 1. Vérification des droits administrateur
net session >nul 2>&1
if not %errorlevel%==0 (
    echo ==========================================
    echo ERREUR : Ce script doit être exécuté en tant qu'administrateur !
    echo Faites un clic droit sur le fichier et choisissez "Exécuter en tant qu'administrateur".
    echo ==========================================
    pause
    exit /b 1
)

REM Le script vit dans scripts\ : la racine du projet est le dossier parent
for %%I in ("%~dp0..") do set "PROJECT_PATH=%%~fI"

echo Configuration du Backend (API) via NSSM (Service Windows)...
REM Suppression de l'ancien service s'il était mal configuré
nssm stop WebPortDashboard
nssm remove WebPortDashboard confirm

REM Installation du service propre
nssm install WebPortDashboard "%PROJECT_PATH%\.venv\Scripts\python.exe" "-m web_port_dashboard.port_dashboard"
nssm set WebPortDashboard AppDirectory "%PROJECT_PATH%"
nssm set WebPortDashboard Start SERVICE_AUTO_START
nssm start WebPortDashboard
echo Service WebPortDashboard configure et demarre.
echo.

echo Nettoyage de l'ancien démarrage (batch invisible inutile)...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Security Shield" /f >nul 2>&1
if exist "%PROJECT_PATH%\start_invisible.vbs" del /f /q "%PROJECT_PATH%\start_invisible.vbs"

echo Configuration du Frontend (Systray) dans le demarrage de l'utilisateur...
cd /d "%PROJECT_PATH%\systray_client"
powershell -ExecutionPolicy Bypass -File .\install_systray_autorun.ps1

echo.
echo ==========================================
echo TOUT EST CONFIGURE AVEC SUCCES !
echo L'API tourne en tache de fond avec droits admin (Service).
echo L'icône de la barre des taches demarrera automatiquement.
echo.
echo Lancement manuel de l'icône de la barre des taches pour la session actuelle...
start "" "bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe"
echo ==========================================
pause
