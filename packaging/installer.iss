; Inno Setup — Cerbere Security Shield (installation par utilisateur)
; Build : iscc packaging\installer.iss   (après build.bat / PyInstaller)

#define AppName "Cerbere Security Shield"
#define AppVersion "0.9.8"
#define AppPublisher "ArchNext"
#define ExeName "CerbereShield.exe"

[Setup]
AppId={{B7E2A1C4-9F3D-4E5A-A1B2-C3D4E5F6A7B8}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
; Installation par utilisateur : pas d'UAC, dossier inscriptible
PrivilegesRequired=lowest
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
Filename: "schtasks"; Parameters: "/delete /tn ""CerbereShield"" /f"; Flags: runhidden; RunOnceId: "DelCerbereTask"
