; ARGUS.EXE installer — Inno Setup script (Phase 5)
;
; Build (on Windows, after the PyInstaller builds):
;     ISCC installer\argus.iss
; Output: dist\ArgusSetup.exe
;
; What this installer does:
;   * Installs Argus.exe (GUI) and ArgusService.exe (service host)
;     into Program Files\Sentinel Safeguard\Argus.
;   * Adds Start Menu shortcuts (desktop icon is optional).
;   * Installs and starts the ArgusProtection Windows service
;     (automatic start — protection is on from boot).
;   * Registers ARGUS.EXE with Windows Security Center as this
;     machine's antivirus provider (root\SecurityCenter2).
;
; Uninstall promise, stated in the uninstaller itself:
;   The quarantine vault and scan history are KEPT when Argus is
;   uninstalled, so reinstalling picks up right where you left off.
;   They are removed only if the user checks "remove all data" on
;   the uninstall form.

#define AppName "ARGUS.EXE"
#define AppVersion "1.0.0"
#define AppPublisher "Sentinel Safeguard LLC"
#define AppExeName "Argus.exe"
#define ServiceExeName "ArgusService.exe"

[Setup]
AppId={{8E7B4A2D-3F5C-4D1E-9A6B-2C8D7E5F4A1B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Sentinel Safeguard\Argus
DefaultGroupName=Sentinel Safeguard\ARGUS.EXE
OutputDir=..\dist
OutputBaseFilename=ArgusSetup
SetupIconFile=..\packaging\argus.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName} — Sentinel Safeguard
UninstallDisplayIcon={app}\{#AppExeName}
InfoBeforeFile=INSTALL-NOTES.txt
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=ARGUS.EXE antivirus — Sentinel Safeguard

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; \
  GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\{#ServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ARGUS.EXE"; Filename: "{app}\{#AppExeName}"
Name: "{group}\ARGUS.EXE Dev Toolkit"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\ARGUS.EXE"; Filename: "{app}\{#AppExeName}"; \
  Tasks: desktopicon

[Run]
; Install the service (automatic start), set crash recovery to
; restart it, register with Windows Security Center, then start it.
Filename: "{app}\{#ServiceExeName}"; Parameters: "install"; \
  StatusMsg: "Installing the ARGUS.EXE protection service..."; \
  Flags: runhidden waituntilterminated
Filename: "sc.exe"; \
  Parameters: "failure ArgusProtection reset= 86400 actions= restart/60000/restart/60000/restart/60000"; \
  StatusMsg: "Configuring service recovery..."; \
  Flags: runhidden waituntilterminated
Filename: "{app}\{#ServiceExeName}"; Parameters: "register"; \
  StatusMsg: "Registering ARGUS.EXE with Windows Security..."; \
  Flags: runhidden waituntilterminated
Filename: "{app}\{#ServiceExeName}"; Parameters: "start"; \
  StatusMsg: "Starting ARGUS.EXE protection..."; \
  Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExeName}"; Description: "Open ARGUS.EXE now"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Reverse order: leave Windows Security, stop the service, remove it.
Filename: "{app}\{#ServiceExeName}"; Parameters: "unregister"; \
  Flags: runhidden waituntilterminated; RunOnceId: "UnregisterAV"
Filename: "{app}\{#ServiceExeName}"; Parameters: "stop"; \
  Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\{#ServiceExeName}"; Parameters: "uninstall"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
var
  RemoveDataCheck: TNewCheckBox;

{ Custom uninstall form: the data choice, in plain language, with
  "keep my data" as the default. }
procedure InitializeUninstallProgressForm();
var
  Note: TNewStaticText;
begin
  RemoveDataCheck := TNewCheckBox.Create(UninstallProgressForm);
  RemoveDataCheck.Parent := UninstallProgressForm;
  RemoveDataCheck.Left := 16;
  RemoveDataCheck.Top := UninstallProgressForm.ClientHeight - 64;
  RemoveDataCheck.Width := UninstallProgressForm.ClientWidth - 32;
  RemoveDataCheck.Caption :=
    'Remove all data too (quarantine vault + scan history)';
  RemoveDataCheck.Checked := False;

  Note := TNewStaticText.Create(UninstallProgressForm);
  Note.Parent := UninstallProgressForm;
  Note.Left := 16;
  Note.Top := UninstallProgressForm.ClientHeight - 44;
  Note.Width := UninstallProgressForm.ClientWidth - 32;
  Note.AutoSize := False;
  Note.WordWrap := True;
  Note.Caption :=
    'Uninstalling ARGUS.EXE always removes the program and the ' +
    'protection service. Your quarantine vault and scan history ' +
    'are KEPT unless you check the box above — so if you reinstall, ' +
    'everything is right where you left it.';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and
     (RemoveDataCheck <> nil) and RemoveDataCheck.Checked then
  begin
    DelTree(ExpandConstant('{localappdata}\Argus'), True, True, True);
    DelTree(ExpandConstant('{commonappdata}\Argus'), True, True, True);
  end;
end;
