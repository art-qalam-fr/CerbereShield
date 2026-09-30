@echo off
echo Fermeture de l'application Systray...
powershell -Command "Start-Process taskkill -ArgumentList '/F /IM WebPortSystray.exe' -Verb RunAs -Wait" 2>nul
echo.
echo Compilation de la nouvelle version...
dotnet publish -c Release -r win-x64 --self-contained
echo.
echo Lancement du nouveau Systray...
start "" "bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe"
pause
