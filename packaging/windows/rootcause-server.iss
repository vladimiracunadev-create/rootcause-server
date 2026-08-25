#define MyAppName "RootCause Server"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Vladimir Acuna"

[Setup]
AppId={{C8EC354A-47D2-4BA0-9D41-833681739A1A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\RootCause
DefaultGroupName=RootCause
ArchitecturesAllowed=x64compatible arm64
ArchitecturesInstallIn64BitMode=x64compatible arm64
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
OutputBaseFilename=RootCause-Server-Setup-{#MyAppVersion}
WizardStyle=modern

[Files]
Source: "..\..\target\release\rootcause-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\release\rootcause-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\RootCause Server"; Filename: "{app}\rootcause-server.exe"; Parameters: "serve"; WorkingDir: "{app}"
Name: "{group}\Documentación de RootCause"; Filename: "{app}\README.md"

[Run]
Filename: "{app}\rootcause-server.exe"; Parameters: "token"; Description: "Generar token inicial en una consola"; Flags: postinstall skipifsilent runascurrentuser

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  MsgBox(
    'El instalador no guarda credenciales. Genere un token y configure el servicio con una cuenta de mínimo privilegio antes de habilitar acceso remoto.',
    mbInformation,
    MB_OK
  );
end;
