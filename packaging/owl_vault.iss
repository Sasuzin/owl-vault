; Instalador do Owl Vault (Inno Setup 6) -> dist\OwlVault-Setup.exe
;
; Gerado por packaging\build.ps1 depois do PyInstaller, que também grava as marcas em
; dist\instalador\ (packaging\installer_files.py). À mão:
;   ISCC /DAppVersion=0.5.0.16 "/DAppLabel=v0.5.0 · build 16 · abc1234" packaging\owl_vault.iss
;
; Regras (docs/WINDOWS.md, "Instalador"):
; * por usuário, sem administrador, sempre em %LOCALAPPDATA%\Programs\Owl Vault — o mesmo lugar
;   em que o OwlVault.exe se instala sozinho (install.py); os atalhos "Abrir com Owl Vault" das
;   pastas protegidas apontam para lá, então a pasta não pode ser escolhida;
; * leva as marcas (versao.txt, versao.sha256, area-de-trabalho.txt) que descrevem exatamente o
;   exe instalado: um OwlVault.exe mais antigo baixado depois não o substitui, e o atalho da Área
;   de Trabalho só existe se a pessoa marcar a opção (o programa não o recria sozinho);
; * nunca instala por cima de uma versão mais nova;
; * a desinstalação NUNCA apaga o perfil (%LOCALAPPDATA%\Owl Vault) nem as pastas protegidas, e
;   avisa antes, se houver perfil: sem o programa, as pastas protegidas não abrem.

#ifndef AppVersion
  #error Rode packaging\build.ps1 (ou passe /DAppVersion=X.Y.Z.B e /DAppLabel=...)
#endif
#ifndef AppLabel
  #define AppLabel AppVersion
#endif
; autoria: igual a AUTHOR em src/owl_vault/__init__.py (test_instalador.py confere)
#define AppAuthor "Luís Felipe Galvão"

[Setup]
AppId={{1EBD1724-39BD-4ADE-B5E3-AD125245BF3F}
AppName=Owl Vault
AppVersion={#AppVersion}
AppVerName=Owl Vault {#AppLabel}
AppPublisher={#AppAuthor}
AppCopyright=© 2026 {#AppAuthor}. Todos os direitos reservados.
AppComments=Desenvolvido por {#AppAuthor}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppAuthor}
VersionInfoCopyright=© 2026 {#AppAuthor}. Todos os direitos reservados.
VersionInfoProductName=Owl Vault
VersionInfoDescription=Instalador do Owl Vault
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\Owl Vault
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousTasks=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=OwlVault-Setup
SetupIconFile=owl.ico
UninstallDisplayIcon={app}\OwlVault.exe
UninstallDisplayName=Owl Vault
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
ShowLanguageDialog=no

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na Área de Trabalho"; GroupDescription: "Atalhos:"

[Files]
Source: "..\dist\OwlVault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\instalador\versao.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\instalador\versao.sha256"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\instalador\area-de-trabalho.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Owl Vault"; Filename: "{app}\OwlVault.exe"; WorkingDir: "{app}"; Comment: "Owl Vault — pastas protegidas"
Name: "{autodesktop}\Owl Vault"; Filename: "{app}\OwlVault.exe"; WorkingDir: "{app}"; Comment: "Owl Vault — pastas protegidas"; Tasks: desktopicon

[Run]
Filename: "{app}\OwlVault.exe"; Description: "Abrir o Owl Vault"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; sobras de uma atualização interrompida (install.py grava .OwlVault.exe.<aleatório>.tmp)
Type: files; Name: "{app}\.*.tmp"
Type: dirifempty; Name: "{app}"

[Code]
const
  InstalledVersionFile = '{localappdata}\Programs\Owl Vault\versao.txt';
  ProfileFile = '{localappdata}\Owl Vault\perfil.owlp';

function InitializeSetup(): Boolean;
var
  Text: AnsiString;
  Installed, Mine: Int64;
begin
  Result := True;
  if LoadStringFromFile(ExpandConstant(InstalledVersionFile), Text) and
     StrToVersion(Trim(String(Text)), Installed) and
     StrToVersion('{#AppVersion}', Mine) and
     (ComparePackedVersion(Installed, Mine) > 0) then
  begin
    SuppressibleMsgBox(
      'Já está instalada uma versão mais nova do Owl Vault (' + Trim(String(Text)) + ').' + #13#10#13#10 +
      'Esta instalação ({#AppVersion}) não vai substituí-la.',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  if FileExists(ExpandConstant(ProfileFile)) or FileExists(ExpandConstant(ProfileFile + '.bak')) then
    Result := SuppressibleMsgBox(
      'Há um perfil do Owl Vault neste computador.' + #13#10#13#10 +
      'Pastas protegidas só abrem com o Owl Vault. Se você não vai instalá-lo de novo, ' +
      'cancele, abra o Owl Vault e use "Remover proteção…" em cada pasta antes de desinstalar.' + #13#10#13#10 +
      'A desinstalação NÃO apaga o perfil nem as pastas protegidas: instalando o Owl Vault ' +
      'de novo neste computador, elas voltam a abrir normalmente.' + #13#10#13#10 +
      'Desinstalar mesmo assim?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDYES) = IDYES;
end;
