@echo off
setlocal

REM Auto-élévation : si pas administrateur, relancer en tant qu'admin
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Demande d'élévation administrateur...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Auto-masquage : relancer en arrière-plan invisible si pas encore masqué
if /i not "%~1"=="-hidden" ( echo CreateObject^("WScript.Shell"^).Run "cmd /c ""%~f0"" -hidden", 0, False > "%TEMP%\ss_run_%~n0.vbs" & wscript "%TEMP%\ss_run_%~n0.vbs" & exit /b )

REM Verifier que le script est lance en tant qu'administrateur
net session >nul 2>&1
if not %errorlevel%==0 (
    echo Ce script doit etre execute en tant qu'administrateur.^& echo.
    exit /b 1
)

REM Appliquer le PLAN DE DURCISSEMENT généré par Cerbere Security Shield
REM Le script vit dans scripts\ : on remonte à la racine du projet

cd /d "%~dp0.."

echo === APPLICATION DU PLAN DE DURCISSEMENT ===
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\powershell\security_hardening.ps1" -Action "harden"
set RC=%errorlevel%

if %RC% equ 0 (
    set "NOTIF_MSG=Plan de durcissement applique."
) else (
    set "NOTIF_MSG=Echec (code %RC%)"
)

if /i not "%~2"=="-q" powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $ni = New-Object System.Windows.Forms.NotifyIcon; $ni.Icon = [System.Drawing.SystemIcons]::Information; $ni.Visible = $true; $ni.ShowBalloonTip(6000, 'Cerbere Security Shield', '%NOTIF_MSG%', [System.Windows.Forms.ToolTipIcon]::Info); Start-Sleep -Seconds 7; $ni.Dispose()"

endlocal & exit /b %RC%
