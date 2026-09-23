; Inno Setup — Cerbere Security Shield (installation par utilisateur)
; Build : iscc packaging\installer.iss   (après build.bat / PyInstaller)

#define AppName "Cerbere Security Shield"
#define AppVersion "0.9.12"
#define AppPublisher "ArchNext"
#define ExeName "CerbereShield.exe"

[Setup]
AppId={{B7E2A1C4-9F3D-4E5A-A1B2-C3D4E5F6A7B8}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
; Installation élevée : nécessaire pour arrêter proprement les processus réseau
PrivilegesRequired=admin
DefaultDirName={localappdata}\Programs\CerbereShield
DefaultGroupName={#AppName}
OutputDir=..\dist\installer
OutputBaseFilename=CerbereShield_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Le pilote WinDivert exigera l'élévation au premier filtrage DNS
SetupIconFile=..\systray_client\cerbere.ico
UninstallDisplayIcon={app}\{#ExeName}

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le bureau"; GroupDescription: "Icônes :"
Name: "startupicon"; Description: "Lancer au démarrage de Windows"; GroupDescription: "Démarrage :"; Flags: unchecked

[Files]
; Application PyInstaller (onedir -> contenu de dist\CerbereShield\)
Source: "..\dist\CerbereShield\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Systray C# (binaire publié, si présent)
Source: "..\systray_client\bin\Release\net6.0-windows\win-x64\publish\WebPortSystray.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; Frontend Desktop Tauri (optionnel, le mode Browser reste disponible)
Source: "..\frontend_react\src-tauri\target\release\cerbere-shield-desktop.exe"; DestDir: "{app}"; DestName: "CerbereDesktop.exe"; Flags: ignoreversion skipifsourcedoesntexist
; Scripts de durcissement (conservés à la racine d'installation)
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Excludes: "__pycache__"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#ExeName}"; AppUserModelID: "Cerbere.SecurityShield"
Name: "{group}\Systray Cerbere"; Filename: "{app}\WebPortSystray.exe"; AppUserModelID: "Cerbere.SecurityShield"; Check: FileExists(ExpandConstant('{app}\WebPortSystray.exe'))
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#ExeName}"; Tasks: desktopicon

[Run]
; CerbereShield.exe demande l'élévation (requireAdministrator) : un raccourci
; dans le dossier Démarrage serait silencieusement ignoré par Windows.
; On utilise donc une tâche planifiée "au logon, privilèges maximaux".
Filename: "schtasks"; Parameters: "/create /tn ""CerbereShield"" /tr ""{app}\{#ExeName}"" /sc onlogon /rl highest /f"; Flags: runhidden; Tasks: startupicon
Filename: "{app}\{#ExeName}"; Verb: "runas"; Description: "Lancer {#AppName}"; Flags: postinstall shellexec skipifsilent

[UninstallRun]
; Arrêt propre du backend avant suppression des fichiers générés/verrouillés.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""Invoke-RestMethod -Method Post -Uri 'http://localhost:4050/api/shutdown' -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Seconds 2"""; Flags: runhidden; RunOnceId: "StopCerbereBackend"
; File d'état du systray séparé : arrêt forcé après la demande propre.
Filename: "{sys}\taskkill.exe"; Parameters: "/f /t /im WebPortSystray.exe"; Flags: runhidden; RunOnceId: "StopCerbereSystray"
Filename: "{sys}\taskkill.exe"; Parameters: "/f /t /im CerbereShield.exe"; Flags: runhidden; RunOnceId: "StopCerbereBackendProcess"
Filename: "schtasks"; Parameters: "/delete /tn ""CerbereShield"" /f"; Flags: runhidden; RunOnceId: "DelCerbereTask"

[UninstallDelete]
; Supprime aussi les logs et dossiers créés après l'installation (logs/_internal).
Type: filesandordirs; Name: "{app}"
