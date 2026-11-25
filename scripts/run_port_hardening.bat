@echo off
setlocal

REM Auto-élévation : si pas administrateur, relancer en tant qu'admin
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande d'élévation administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Verifier que le script est lance en tant qu'administrateur
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Ce script doit etre execute en tant qu'administrateur.^& echo.
    pause
    exit /b 1
)

REM Aller dans le répertoire du projet (le script vit dans scripts\)
cd /d "%~dp0.."

REM Lancer le script de durcissement avec le plan détecté automatiquement (mode RÉEL)
powershell -ExecutionPolicy Bypass -File ".\scripts\powershell\security_hardening.ps1"

pause
endlocal
