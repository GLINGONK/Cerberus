; Cerberus — script Inno Setup
;
; Tauri already produces an NSIS installer. This Inno Setup alternative packages
; the same executable with additional Windows checks.
;
; Prerequisite: build the application first.
;   cargo tauri build
; Puis :
;   iscc installer\cerberus.iss

#define AppName        "Cerberus"
#define AppVersion     "0.1.0"
#define AppPublisher   "GLINGONK"
#define AppExeName     "cerberus-app.exe"
#define SourceExe      "..\target\release\cerberus-app.exe"

[Setup]
AppId={{9C4B1E7A-3D2F-4A88-9E51-CB7A2F0D6E13}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir=..\target\release\bundle\inno
OutputBaseFilename=Cerberus_{#AppVersion}_x64_setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; L'application est 64 bits uniquement.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809 minimum : WebView2 n'est pas disponible avant.
MinVersion=10.0.17763
PrivilegesRequired=admin
SetupIconFile=..\app\src-tauri\icons\icon.ico
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE

[Languages]
Name: "french";  MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "associate";   Description: "Associate .cbv files with Cerberus"; GroupDescription: "Integration"

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\SECURITY-DESIGN.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}";        Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}";  Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Vault file-format association.
Root: HKA; Subkey: "Software\Classes\.cbv"; ValueType: string; ValueName: ""; ValueData: "Cerberus.Vault"; Flags: uninsdeletevalue; Tasks: associate
Root: HKA; Subkey: "Software\Classes\Cerberus.Vault"; ValueType: string; ValueName: ""; ValueData: "Cerberus vault"; Flags: uninsdeletekey; Tasks: associate
Root: HKA; Subkey: "Software\Classes\Cerberus.Vault\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExeName},0"; Tasks: associate
Root: HKA; Subkey: "Software\Classes\Cerberus.Vault\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"" ""%1"""; Tasks: associate

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
{ WebView2 is the only external runtime dependency. It is included with
  Windows 11 and current Windows 10 installations, but is not guaranteed. }
function WebView2Installed(): Boolean;
var
  Version: String;
begin
  Result :=
    RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version) or
    RegQueryStringValue(HKEY_CURRENT_USER,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version);
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not WebView2Installed() then
  begin
    if MsgBox('Microsoft Edge WebView2 is not installed. Cerberus cannot display '
              + 'its interface without this component.'#13#10#13#10
              + 'Install it from:'#13#10
              + 'https://developer.microsoft.com/microsoft-edge/webview2/'#13#10#13#10
              + 'Continue anyway?',
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

{ Vaults remain outside the installation directory and are never removed. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox('Cerberus has been uninstalled.'#13#10#13#10
           + 'Your vault (.cbv) and key files were not modified. '
           + 'They remain where you saved them.',
           mbInformation, MB_OK);
end;
