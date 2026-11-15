; Inno Setup Script for AegisRE
#define MyAppName "AegisRE"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Aegis Project"
#define MyAppURL "https://github.com/aegis-re"
#define MyAppExeName "aegis.exe"

[Setup]
AppId={{9B78619A-5991-4D66-8A33-E18CF731998A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=C:\Build\Release
OutputBaseFilename=AegisRE-Setup-v1.0.0-win-x64
SetupIconFile=C:\Build\AegisRE\assets\aegis.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "envPath"; Description: "Add AegisRE to system PATH environment variable"; GroupDescription: "System Integration:"

[Files]
Source: "C:\Build\AegisRE_Portable\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName} Terminal"; Filename: "{cmd}"; Parameters: "/K ""{app}\{#MyAppExeName}"" --help"; IconFilename: "{app}\assets\aegis.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{cmd}"; Parameters: "/K ""{app}\{#MyAppExeName}"" --help"; IconFilename: "{app}\assets\aegis.ico"; Tasks: desktopicon

[Registry]
; Add {app} to PATH
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: envPath

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  { Look for the path with leading and trailing semicolons }
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
