param(
    [switch]$Uninstall
)

# Script d’enregistrement / suppression de l’auto-démarrage de la systray WebPortSystray
# HKCU\Software\Microsoft\Windows\CurrentVersion\Run

$runKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$appName    = 'WebPortSystray'

if ($Uninstall) {
    if (Get-ItemProperty -Path $runKeyPath -Name $appName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $runKeyPath -Name $appName -ErrorAction SilentlyContinue
        Write-Host "Auto-démarrage de $appName supprimé pour l’utilisateur courant." -ForegroundColor Green
    } else {
        Write-Host "Aucune entrée d’auto-démarrage trouvée pour $appName." -ForegroundColor Yellow
    }
    return
}

# Construction du chemin absolu vers l’exécutable Release
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath    = Join-Path $scriptRoot 'bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe'

if (-not (Test-Path -Path $exePath)) {
    Write-Host "Exécutable introuvable: $exePath" -ForegroundColor Red
    Write-Host "Construisez d’abord l’application en Release :" -ForegroundColor Yellow
    Write-Host "  dotnet build -c Release" -ForegroundColor Yellow
    return
}

# Ajout / mise à jour de l’entrée Run pour l’utilisateur courant
$quotedPath = '"' + $exePath + '"'
New-Item -Path $runKeyPath -Force | Out-Null
Set-ItemProperty -Path $runKeyPath -Name $appName -Value $quotedPath

Write-Host "Auto-démarrage configuré pour $appName : $exePath" -ForegroundColor Green
Write-Host "L’application systray sera lancée automatiquement à l’ouverture de session." -ForegroundColor Green
