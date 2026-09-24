; Dependency-installer fixture (Phase 4A Task 6): a tiny silent-capable NSIS installer standing in for a vendor
; redistributable. Built with: makensis -NOCD tools/fixtures/dep-installer.nsi (by tools/build-fixtures.sh).
; It writes BOTH marker kinds the dependency engine understands:
;   file:     C:\rt-dep-marker.txt
;   registry: HKLM\Software\RuntimeDepFixture  "Installed" = 1 (DWORD). NSIS is 32-bit, so on a win64 prefix this
;             lands under HKLM\Software\Wow6432Node\RuntimeDepFixture (the marker lookup checks both views).
; `dep-installer.exe /S` runs with no dialogs. It does nothing network-related.

Name "Runtime Dependency Fixture"
OutFile "tests/fixtures/build/dep-installer.exe"
RequestExecutionLevel admin
SilentInstall normal

Section "Install"
  SetAutoClose true
  FileOpen $0 "C:\rt-dep-marker.txt" w
  FileWrite $0 "installed by dep-installer.nsi$\r$\n"
  FileClose $0
  WriteRegDWORD HKLM "Software\RuntimeDepFixture" "Installed" 1
SectionEnd
