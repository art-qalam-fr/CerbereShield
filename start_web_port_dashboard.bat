@echo off
setlocal

REM Auto-élévation : si pas administrateur, relancer en tant qu'admin
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande d'élévation administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Aller dans le repertoire du projet (chemin corrige)
cd /d  %~dp0

REM Verifier que Python est installe
"%~dp0.venv\Scripts\python.exe" --version >nul 2>&1
if not %errorlevel%==0 (
    echo Python n'est pas installe ou pas dans le PATH.
    pause
    exit /b 1
)

REM Verifier les dependances
echo Verification des dependances...
"%~dp0.venv\Scripts\pip.exe" show fastapi uvicorn >nul 2>&1
if not %errorlevel%==0 (
    echo Installation des dependances manquantes...
    "%~dp0.venv\Scripts\pip.exe" install fastapi uvicorn
)

REM Lancer le serveur FastAPI de Cerbere Security Shield
echo Demarrage de Cerbere Security Shield...
start "Cerbere Security Shield API" cmd /c ""%~dp0.venv\Scripts\python.exe" -m web_port_dashboard.port_dashboard"

REM Attendre demarrage serveur
echo Attente du demarrage du serveur...
timeout /t 3 /nobreak >nul

REM Ouvrir navigateur
echo Ouverture du navigateur...
start "" "http://localhost:4050/"

echo Dashboard web demarre sur http://localhost:4050/
pause
