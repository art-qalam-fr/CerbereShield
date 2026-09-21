@echo off
REM Script pour créer des raccourcis sur le bureau

setlocal EnableDelayedExpansion

echo Creation des raccourcis sur le bureau...
echo.

REM Obtenir le chemin du bureau
set "DESKTOP=%USERPROFILE%\Desktop"
REM Le script vit dans scripts\ : la racine du projet est le dossier parent
for %%I in ("%~dp0..") do set "PROJECT_PATH=%%~fI"

echo Bureau: !DESKTOP!
echo Projet: !PROJECT_PATH!
echo.

REM Créer le raccourci pour l'application complète
echo Creation du raccourci: Cerbere Security Shield (Application Complete)
powershell -Command ^
"$ws = New-Object -ComObject WScript.Shell; ^
$s = $ws.CreateShortcut('!DESKTOP!\Cerbere Security Shield.lnk'); ^
$s.TargetPath = '!PROJECT_PATH!\start_complete_application.bat'; ^
$s.WorkingDirectory = '!PROJECT_PATH!'; ^
$s.Description = 'Lancer Cerbere Security Shield (Web + Systray)'; ^
$s.Save()"

REM Créer le raccourci pour le durcissement des ports
echo Creation du raccourci: Durcissement des Ports
powershell -Command ^
"$ws = New-Object -ComObject WScript.Shell; ^
$s = $ws.CreateShortcut('!DESKTOP!\Durcissement Ports.lnk'); ^
$s.TargetPath = '!PROJECT_PATH!\scripts\appliquer_plan_durcissement_ports.bat'; ^
$s.WorkingDirectory = '!PROJECT_PATH!'; ^
$s.Description = 'Appliquer le durcissement des ports'; ^
$s.Save()"

REM Créer le raccourci pour la libération des ports
echo Creation du raccourci: Liberation des Ports
powershell -Command ^
"$ws = New-Object -ComObject WScript.Shell; ^
$s = $ws.CreateShortcut('!DESKTOP!\Liberation Ports.lnk'); ^
$s.TargetPath = '!PROJECT_PATH!\scripts\appliquer_plan_liberation_ports.bat'; ^
$s.WorkingDirectory = '!PROJECT_PATH!'; ^
$s.Description = 'Liberer les ports bloques'; ^
$s.Save()"

REM Créer le raccourci pour le dashboard web uniquement
echo Creation du raccourci: Dashboard Web Only
powershell -Command ^
"$ws = New-Object -ComObject WScript.Shell; ^
$s = $ws.CreateShortcut('!DESKTOP!\Dashboard Web.lnk'); ^
$s.TargetPath = '!PROJECT_PATH!\start_web_port_dashboard.bat'; ^
$s.WorkingDirectory = '!PROJECT_PATH!'; ^
$s.Description = 'Lancer uniquement le dashboard web'; ^
$s.Save()"

echo.
echo ========================================
echo   SUCCES: Raccourcis crees sur le bureau!
echo ========================================
echo.
echo Raccourcis crees:
echo - Cerbere Security Shield.lnk (Application complete)
echo - Durcissement Ports.lnk (Durcissement des ports)
echo - Liberation Ports.lnk (Liberation des ports)
echo - Dashboard Web.lnk (Dashboard web uniquement)
echo.
echo Vous pouvez maintenant lancer l'application directement depuis le bureau!
echo.
pause
