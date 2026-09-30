@echo off
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande des droits Administrateur pour forcer l'arret...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b 0
)

echo Arret du service WebPortDashboard (s'il existe)...
nssm stop WebPortDashboard >nul 2>&1
nssm remove WebPortDashboard confirm >nul 2>&1

echo Nettoyage brutal du port 4050...
for /f "tokens=5" %%a in ('netstat -aon ^| find "4050" ^| find "LISTENING"') do (
    echo Destruction du processus %%a...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo ==============================================
echo TERMINE ! Le port 4050 a ete libere de force.
echo Vous pouvez maintenant relancer votre script.
echo ==============================================
pause
