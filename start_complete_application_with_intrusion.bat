@echo off
setlocal

REM Auto-élévation : si pas administrateur, relancer en tant qu'admin
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande d'élévation administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if "%~1"=="-invisible" goto :run_invisible

REM Lance le script de manière invisible en utilisant PowerShell
powershell -WindowStyle Hidden -Command "Start-Process cmd -ArgumentList '/c', '\"%~dpnx0\"', '-invisible' -WindowStyle Hidden"
exit /b

:run_invisible
cd /d "%~dp0"

REM Tuer tous les processus utilisant le port 4050
powershell -Command "$p = Get-NetTCPConnection -LocalPort 4050 -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id $p.OwningProcess -Force -ErrorAction SilentlyContinue }"

REM Recompiler le systray si les sources C# sont plus recentes que l'exe
powershell -Command "$exe='%~dp0systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe'; if (Test-Path $exe) { $src=Get-ChildItem '%~dp0systray_client\*.cs' | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($src -and $src.LastWriteTime -gt (Get-Item $exe).LastWriteTime) { Push-Location '%~dp0systray_client'; dotnet publish -c Release -r win-x64 --self-contained | Out-Null; Pop-Location } }"

REM Lancement de l'icône dans la barre des taches (Systray) AVANT pip install
REM pour que l'icône apparaisse immédiatement
if exist "%~dp0systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe" (
    tasklist /FI "IMAGENAME eq WebPortSystray.exe" | find /I "WebPortSystray.exe" >nul || start "" "%~dp0systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe"
)

REM Installation des dépendances (avec retry : le backend qui vient d'etre
REM tue peut laisser des verrous transitoires sur les fichiers du .venv)
"%~dp0.venv\Scripts\python.exe" -m pip install -r requirements.txt > "%TEMP%\cerbere_pip_install.log" 2>&1
if %errorlevel% neq 0 (
    timeout /t 3 /nobreak >nul
    "%~dp0.venv\Scripts\python.exe" -m pip install -r requirements.txt >> "%TEMP%\cerbere_pip_install.log" 2>&1
    if errorlevel 1 (
        powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Erreur critique : Impossible d''installer les dependances. Voir %TEMP%\cerbere_pip_install.log', 'Erreur Cerbere Security Shield', 'OK', 'Error')"
        exit /b
    )
)

cd web_port_dashboard
REM Lancement du backend (le fichier log se trouve dans les fichiers temporaires)
"%~dp0.venv\Scripts\python.exe" port_dashboard.py > "%TEMP%\security_shield_crash.log" 2>&1

if %errorlevel% neq 0 (
    REM Le backend est peut-etre en cours de redemarrage (relaunch) : attendre jusqu'a ~25 s
    REM avant de conclure a un crash reel.
    powershell -Command "$ok=$false; for ($i=0; $i -lt 5; $i++) { try { (Invoke-WebRequest -Uri 'http://localhost:4050/api/protection/state' -TimeoutSec 3 -UseBasicParsing) | Out-Null; $ok=$true; break } catch { Start-Sleep -Seconds 5 } }; if ($ok) { exit 0 } else { exit 1 }"
    if errorlevel 1 (
        powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Erreur critique : Le serveur a crashe. Voir %TEMP%\security_shield_crash.log', 'Erreur', 'OK', 'Error')"
    )
)
exit /b
