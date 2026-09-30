@echo off
setlocal

REM Auto-élévation : si pas administrateur, relancer en tant qu'admin
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande d'élévation administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Aller dans le repertoire du projet
cd /d %~dp0

REM Verifier que Python est installe
"%~dp0.venv\Scripts\python.exe" --version >nul 2>&1
if not %errorlevel%==0 (
    echo Python n'est pas installe ou pas dans le PATH.
    pause
    exit /b 1
)

REM Verifier les dependances
echo Verification des dependances...
"%~dp0.venv\Scripts\pip.exe" show fastapi uvicorn psutil pyyaml >nul 2>&1
if not %errorlevel%==0 (
    echo Installation des dependances manquantes...
    "%~dp0.venv\Scripts\pip.exe" install -r requirements.txt
)

REM Verifier si le systray est compile (recompiler si les sources sont plus recentes)
if not exist "systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe" (
    echo Compilation du systray...
    cd systray_client
    dotnet publish -c Release -r win-x64 --self-contained
    cd ..
) else (
    powershell -Command "$exe='systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe'; $src=Get-ChildItem 'systray_client\*.cs' | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($src -and $src.LastWriteTime -gt (Get-Item $exe).LastWriteTime) { Write-Host 'Sources systray modifiees, recompilation...'; Push-Location systray_client; dotnet publish -c Release -r win-x64 --self-contained | Out-Null; Pop-Location }"
)

REM Tuer tout processus occupant le port 4050 (evite un backend zombie)
echo Liberation du port 4050...
powershell -Command "$p = Get-NetTCPConnection -LocalPort 4050 -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id $p.OwningProcess -Force -ErrorAction SilentlyContinue }"

REM Lancer le serveur FastAPI de Cerbere Security Shield
echo Demarrage de Cerbere Security Shield...
start "Cerbere Security Shield API" /B "%~dp0.venv\Scripts\pythonw.exe" -m web_port_dashboard.port_dashboard

REM Attendre demarrage serveur puis verifier qu'il repond bien
echo Attente du demarrage du serveur...
powershell -Command "$ok=$false; for ($i=0; $i -lt 6; $i++) { try { (Invoke-WebRequest -Uri 'http://localhost:4050/api/protection/state' -TimeoutSec 3 -UseBasicParsing) | Out-Null; $ok=$true; break } catch { Start-Sleep -Seconds 3 } }; if (-not $ok) { Write-Host 'ERREUR: le serveur ne repond pas sur le port 4050.'; exit 1 }"
if errorlevel 1 (
    echo Le backend n'a pas demarre correctement. Consultez logs\cerbere.log.
    pause
    exit /b 1
)

REM Lancer le systray (sans doublon : on ne relance pas s'il tourne deja)
echo Demarrage du systray...
if exist "systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe" (
    tasklist /FI "IMAGENAME eq WebPortSystray.exe" | find /I "WebPortSystray.exe" >nul || start "" "systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe"
) else (
    echo Attention: Le systray n'a pas pu etre compile.
    echo Veuillez installer .NET 6.0 SDK pour compiler le systray.
)

REM Ouvrir navigateur
echo Ouverture du navigateur...
start "" "http://localhost:4050/"

echo.
echo Dashboard web demarre sur http://localhost:4050/
echo L'icône de l'application devrait apparaitre dans la barre des taches.
echo.
pause
