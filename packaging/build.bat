@echo off
REM ============================================================
REM  Build packaging — Cerbere Security Shield (option 1)
REM  1. PyInstaller -> dist\CerbereShield\  (onedir)
REM  2. Inno Setup -> dist\installer\CerbereShield_Setup.exe
REM
REM  Debug console : set CERBERE_BUILD_DEBUG=1 avant le build.
REM ============================================================
setlocal
cd /d "%~dp0.."

set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" ( echo [ERR] venv introuvable: %PY% & exit /b 1 )

echo [1/3] Verification de PyInstaller...
"%PY%" -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo      Installation de pyinstaller...
    "%PY%" -m pip install "pyinstaller>=6.5" || exit /b 1
)

echo [2/3] Build PyInstaller (dist\CerbereShield)...
"%PY%" -m PyInstaller --noconfirm --clean packaging\cerbere.spec || exit /b 1

echo [3/4] Systray .NET (WebPortSystray.exe)...
where dotnet >nul 2>&1
if errorlevel 1 (
    echo      [INFO] dotnet introuvable — le systray ne sera pas inclus.
) else (
    pushd systray_client
    dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o bin\Release\net6.0-windows\win-x64\publish
    if errorlevel 1 ( popd & exit /b 1 )
    popd
)

echo [4/5] Frontend React + Desktop Tauri...
where npm >nul 2>&1
if errorlevel 1 (
    echo      [INFO] npm introuvable — le Desktop Tauri ne sera pas inclus.
) else (
    pushd frontend_react
    call npm ci
    call npm run tauri:build
    if errorlevel 1 ( popd & exit /b 1 )
    popd
)

if not exist "frontend_react\src-tauri\target\release\cerbere-shield-desktop.exe" (
    echo      [INFO] Binaire Desktop Tauri absent — mode Browser conserve.
)

echo [5/5] Installeur Inno Setup...
where iscc >nul 2>&1
if errorlevel 1 (
    echo      [INFO] iscc introuvable — installeur non genere.
    echo      Le dossier dist\CerbereShield\ reste utilisable en mode portable.
    exit /b 0
)
iscc packaging\installer.iss || exit /b 1
echo      [OK] dist\installer\CerbereShield_Setup.exe
endlocal
