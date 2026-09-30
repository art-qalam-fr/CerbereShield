# Script de publication du Systray Security Sheeld
# Génère un exécutable autonome (self-contained) pour Windows.

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$CsprojPath = Join-Path $ProjectDir "WebPortSystray.csproj"

Write-Host "--- Publication du Systray Client ---" -ForegroundColor Cyan

if (-not (Test-Path $CsprojPath)) {
    Write-Error "Fichier projet introuvable : $CsprojPath"
    exit 1
}

# Publication en mode autonome, fichier unique, sans dépendance au runtime .NET installé sur la machine cible
dotnet publish $CsprojPath `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:PublishReadyToRun=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -o "$ProjectDir\bin\Release\net6.0-windows\win-x64\publish"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nSuccès ! L'exécutable autonome se trouve dans : $ProjectDir\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe" -ForegroundColor Green
} else {
    Write-Host "`nErreur lors de la publication." -ForegroundColor Red
}
