@echo off
setlocal

REM Verifier que le script est lance en tant qu'administrateur
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Ce script doit etre execute en tant qu'administrateur.^& echo.
    pause
    exit /b 1
)

REM Aller dans le répertoire du projet (le script vit dans scripts\)
cd /d "%~dp0.."

REM Lancer le script de durcissement en mode DRY RUN (simulation)
powershell -ExecutionPolicy Bypass -File ".\scripts\powershell\security_hardening.ps1" -DryRun

pause
endlocal
