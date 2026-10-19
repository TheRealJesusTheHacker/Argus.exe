; ARGUS.EXE installer — Inno Setup script (premium edition)
;
; Build (on Windows, after the PyInstaller builds):
;     ISCC installer\argus.iss
; Output: dist\ArgusSetup.exe
;
; What this installer does:
;   * Installs Argus.exe (GUI) and ArgusService.exe (service host)
;     into Program Files\Sentinel Safeguard\Argus.
;   * Adds Start Menu shortcuts (desktop icon is optional).
;   * On upgrade, stops the running protection service first so
;     the install never fights a locked file.
;   * Installs and starts the ArgusProtection Windows service
;     (automatic start, crash recovery = restart).
;   * Registers ARGUS.EXE with Windows Security Center as this
;     machine's antivirus provider (root\SecurityCenter2).
;   * VERIFIES at the end that the protection service is actually
;     RUNNING — and says so plainly on the finish page (or warns,
;     loudly and clearly, if it is not).
;
; Uninstall promise, stated in the uninstaller itself:
;   The quarantine vault and scan history are KEPT when Argus is
;   uninstalled, so reinstalling picks up right where you left off.
;   They are removed only if the user checks "remove all data" on
;   the uninstall form.

#define AppName "ARGUS.EXE"
#define AppVersion "1.0.2"
#define AppPublisher "Sentinel Safeguard LLC"
#define AppExeName "Argus.exe"
#define ServiceExeName "ArgusService.exe"

[Setup]
AppId={{8E7B4A2D-3F5C-4D1E-9A6B-2C8D7E5F4A1B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://sentinelsafeguard.net
AppSupportURL=https://sentinelsafeguard.net
AppUpdatesURL=https://github.com/TheRealJesusTheHacker/Argus.exe/releases
AppContact=Sentinelsafeguard@outlook.com
AppCopyright=Copyright (C) 2026 Sentinel Safeguard LLC. All rights reserved.
AppComments=Antivirus and malware protection by Sentinel Safeguard LLC — Security For Everyone.
DefaultDirName={autopf}\Sentinel Safeguard\Argus
DefaultGroupName=Sentinel Safeguard\ARGUS.EXE
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
UsePreviousTasks=yes
OutputDir=..\dist
OutputBaseFilename=ArgusSetup
SetupIconFile=..\packaging\argus.ico
LicenseFile=LICENSE.txt
InfoBeforeFile=INSTALL-NOTES.txt
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile=assets\wizard-image.bmp
WizardSmallImageFile=assets\wizard-small-image.bmp
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupMutex=ArgusSetupMutex
CloseApplications=yes
UninstallDisplayName={#AppName} — Sentinel Safeguard
UninstallDisplayIcon={app}\{#AppExeName}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoDescription=ARGUS.EXE Setup — Sentinel Safeguard antivirus
VersionInfoCopyright=Copyright (C) 2026 {#AppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to ARGUS.EXE
WelcomeLabel2=Argus watches this PC so threats don't get a head start.%n%nSignatures, behavior rules, and 30 plain-language warning signs — working together from the moment Windows boots. Setup will now install Argus and turn protection on.%n%nSecurity For Everyone.
FinishedHeadingLabel=ARGUS.EXE is protecting this PC
FinishedLabel=Setup is complete and the Argus protection service has been started. Argus now opens with a short first-run guide: pick the folders to watch, choose what happens when a threat is found, and run the built-in self-test to watch detection work.%n%nThank you for choosing Sentinel Safeguard.
ClickNext=Click Next to continue.
LicenseLabel3=Argus is provided by Sentinel Safeguard LLC. Please read this agreement before continuing.

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
  GroupDescription: "Shortcuts:"
Name: "trayautostart"; Description: "Open the Argus window when I sign in to Windows"; \
  GroupDescription: "Startup:"; Flags: unchecked

[Dirs]
; The shared Argus data root (config, signature DB, vault, history)
; lives in ProgramData so the LocalSystem service and every user's
; GUI/CLI see the same data. Create it at install time with user
; modify rights — otherwise the service (running as SYSTEM) would
; create it first and standard-user processes could not write the
; shared vault/history.
Name: "{commonappdata}\Argus"; Permissions: users-modify

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\{#ServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "INSTALL-NOTES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKLM; Subkey: "Software\Sentinel Safeguard\Argus"; \
  ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; \
  Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Sentinel Safeguard\Argus"; \
  ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "ArgusTray"; \
  ValueData: """{app}\{#AppExeName}"""; Tasks: trayautostart; \
  Flags: uninsdeletevalue

[Icons]
Name: "{group}\ARGUS.EXE"; Filename: "{app}\{#AppExeName}"; \
  Comment: "Open ARGUS.EXE — antivirus and malware protection"
Name: "{group}\ARGUS.EXE Dev Toolkit"; Filename: "{app}\{#AppExeName}"; \
  Parameters: "--page devtoolkit"; \
  Comment: "Open ARGUS.EXE on the Dev Toolkit page"
Name: "{autodesktop}\ARGUS.EXE"; Filename: "{app}\{#AppExeName}"; \
  Tasks: desktopicon; Comment: "ARGUS.EXE — Sentinel Safeguard"

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
  ServiceVerified: Boolean;

{ Upgrade-safe: if an older Argus is already protecting this PC,
  stop and remove its service before files are replaced, so the
  install never fails on a locked, running service binary. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ServiceExe: String;
begin
  Result := '';
  ServiceExe := ExpandConstant('{app}\{#ServiceExeName}');
  if FileExists(ServiceExe) then
  begin
    Exec(ServiceExe, 'stop', '', SW_HIDE, ewWaitUntilTerminated,
      ResultCode);
    Exec(ServiceExe, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated,
      ResultCode);
  end;
end;

{ Self-verification: after the service start step, ask Windows
  whether ArgusProtection is actually RUNNING. The finish page
  tells the truth either way — no silent failure. }
function ServiceIsRunning(): Boolean;
var
  ResultCode: Integer;
  OutFile: String;
  Lines: TArrayOfString;
  I: Integer;
begin
  Result := False;
  OutFile := ExpandConstant('{tmp}\argus-svc-state.txt');
  if Exec(ExpandConstant('{cmd}'),
    '/C sc query ArgusProtection > "' + OutFile + '" 2>&1', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringsFromFile(OutFile, Lines) then
      for I := 0 to GetArrayLength(Lines) - 1 do
        if Pos('RUNNING', Lines[I]) > 0 then
          Result := True;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    ServiceVerified := ServiceIsRunning();
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not ServiceVerified then
  begin
    WizardForm.FinishedHeadingLabel.Caption :=
      'ARGUS.EXE is installed — one thing needs your attention';
    WizardForm.FinishedLabel.Caption :=
      'Argus is installed, but the protection service is not ' +
      'running yet, so real-time protection is OFF. Restarting ' +
      'Windows usually fixes this. If it does not, open Argus ' +
      'and check the Dashboard, or contact Sentinel Safeguard ' +
      'at Sentinelsafeguard@outlook.com.' + #13#10#13#10 +
      'On-demand scanning in the Argus app works either way.';
  end;
end;

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
