@echo off
setlocal
REM ============================================================
REM  Cerbere Security Shield - Export "repo public"
REM  Produit une copie propre du projet SANS historique ni
REM  elements de developpement, prete a etre poussee sur un
REM  nouveau depot GitHub public.
REM
REM  Usage :  packaging\export_public.bat  C:\chemin\CerbereShield
REM ============================================================

if "%~1"=="" (
  echo Usage: %~nx0 ^<dossier_cible_vide^>
  exit /b 1
)

for %%I in ("%~dp0..") do set "SRC=%%~fI"
set "DST=%~f1"

echo Source : %SRC%
echo Cible  : %DST%
echo.

REM --- Copie miroir avec exclusions (noms simples = exclus a tout niveau) ---
robocopy "%SRC%" "%DST%" /MIR /NFL /NDL /NJH /NP /R:1 /W:1 ^
  /XD .git .venv .agent .kilo .vscode .pytest_cache .benchmarks ^
      .claude .devin .codeium backup build dist logs logo ^
      memory-database publish_staging semantic-cache-data tasks ^
      "PRD*" __pycache__ state node_modules bin obj publish ^
  /XF .env *.pyc *.db-shm *.db-wal audit_data.json AGENTS.md .DS_Store ^
      *.code-workspace image.png nul

if errorlevel 8 (
  echo [ERREUR] robocopy a echoue.
  exit /b 1
)

echo.
echo === Export termine. Initialisation du depot public ===
pushd "%DST%"

if not exist ".git" git init -b main
git add -A
if errorlevel 1 (
  echo [ERREUR] git add a echoue ^(index verrouille ?^).
  popd
  exit /b 1
)
git diff --cached --quiet
if not errorlevel 1 (
  echo [INFO] Aucun changement a commiter.
) else (
  git -c user.name="Cerbere Shield" -c user.email="contact@cerbere-shield.local" ^
      commit -m "Cerbere Security Shield - public release"
)

echo.
echo Prochaines etapes :
echo   1. Cree le repo public sur GitHub (ex. github.com/^<compte^>/CerbereShield)
echo   2. git remote add origin https://github.com/^<compte^>/CerbereShield.git
echo   3. git push -u origin main
popd
