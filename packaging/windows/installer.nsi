!include "MUI2.nsh"

Name "ToxTunnel"
OutFile "toxtunnel-installer.exe"
InstallDir "$PROGRAMFILES64\ToxTunnel"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "..\..\build\Release\*.*"

  CreateDirectory "$APPDATA\toxtunnel"
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" \
      "Path" "$%PATH%;$INSTDIR"

  nsExec::ExecToLog 'sc create ToxTunnel binPath= "\"$INSTDIR\toxtunnel.exe\" -c \"$APPDATA\toxtunnel\config.yaml\" --service" start= auto'
SectionEnd

Section "Uninstall"
  nsExec::ExecToLog "sc stop ToxTunnel"
  nsExec::ExecToLog "sc delete ToxTunnel"
  RMDir /r "$INSTDIR"
SectionEnd
