; Minimal NSIS installer fixture (Task 0 of Phase 3).
; Built with: makensis -NOCD tools/fixtures/hello.nsi (invoked from repo root by tools/build-fixtures.sh).
; Payload (hello64.exe) comes from tools/build-fixtures.sh's mingw-w64 build; not rebuilt here.
; Silent install: hello-nsis.exe /S -- no dialogs, no user interaction, and no output artifacts differ
; from a normal run (SetAutoClose makes the normal run finish on its own too).

!define APP_NAME "Runtime Fixture NSIS"
!define APP_DIR  "RuntimeFixtureNsis"

Name "${APP_NAME}"
OutFile "tests/fixtures/build/hello-nsis.exe"
InstallDir "$PROGRAMFILES64\${APP_DIR}"
RequestExecutionLevel admin

Section "Install"
  SetAutoClose true
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File "tests/fixtures/build/hello64.exe"

  CreateDirectory "$SMPROGRAMS\${APP_DIR}"
  CreateShortcut "$SMPROGRAMS\${APP_DIR}\${APP_NAME}.lnk" "$INSTDIR\hello64.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_DIR}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_DIR}" "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$INSTDIR\hello64.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${APP_DIR}\${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_DIR}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_DIR}"
SectionEnd
