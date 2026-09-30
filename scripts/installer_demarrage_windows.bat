@echo off
REM Script pour gérer Cerbere Security Shield au démarrage de Windows

setlocal EnableDelayedExpansion

REM Vérifier si on demande à supprimer
if /i "%1"=="remove" goto :REMOVE
if /i "%1"=="uninstall" goto :REMOVE

REM Obtenir le chemin complet du projet (le script vit dans scripts\)
for %%I in ("%~dp0..") do set "PROJECT_PATH=%%~fI"

REM Nom de l'application dans le démarrage
set "APP_NAME=Cerbere Security Shield"

REM Chemin du script de lancement
set "BAT_PATH=!PROJECT_PATH!\start_invisible.vbs"

echo Configuration du demarrage automatique de Cerbere Security Shield...
echo.
echo Chemin du projet: !PROJECT_PATH!
echo Script de lancement: !BAT_PATH!
echo.

REM Verifier que le script existe
if not exist "!BAT_PATH!" (
    echo ERREUR: Le script de lancement n'existe pas:
    echo !BAT_PATH!
    echo.
    pause
    exit /b 1
)

REM Ajouter au démarrage via le registre
echo Ajout de l'application au demarrage de Windows...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "!APP_NAME!" /t REG_SZ /d "wscript.exe \"!BAT_PATH!\"" /f

if !errorlevel! equ 0 (
    echo.
    echo ========================================
    echo   SUCCES: Cerbere Security Shield est maintenant configure pour se lancer au demarrage de Windows!
    echo ========================================
    echo.
    echo Pour verifier: 
    echo - Ouvrez le Gestionnaire des taches (Ctrl+Shift+Esc)
    echo - Allez dans l'onglet "Demarrage"
    echo - Vous devriez voir "Cerbere Security Shield" dans la liste
    echo.
    echo Pour desactiver le demarrage automatique:
    echo - Executez: installer_demarrage_windows.bat remove
    echo - Ou utilisez le Gestionnaire des taches
    echo.
) else (
    echo.
    echo ERREUR: Impossible d'ajouter l'application au demarrage.
    echo Veuillez executer ce script en tant qu'administrateur.
    echo.
)

pause
exit /b 0

:REMOVE
set "APP_NAME=Cerbere Security Shield"
echo Suppression du demarrage automatique de Cerbere Security Shield...
echo.

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "!APP_NAME!" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Security Shield" /f >nul 2>&1

if !errorlevel! equ 0 (
    echo.
    echo ========================================
    echo   SUCCES: Cerbere Security Shield a ete supprime du demarrage de Windows!
    echo ========================================
    echo.
) else (
    echo.
    echo INFO: Cerbere Security Shield n'etait pas configure pour se lancer au demarrage.
    echo Ou il a deja ete supprime.
    echo.
)

pause
exit /b 0
