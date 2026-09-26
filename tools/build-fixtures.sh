#!/bin/sh
# Builds Windows test executables into tests/fixtures/build/ (gitignored). Needs mingw-w64.
set -eu
cd "$(dirname "$0")/.."
out=tests/fixtures/build
mkdir -p "$out"
for arch in x86_64 i686; do
  tag=64; [ "$arch" = i686 ] && tag=32
  cc="$arch-w64-mingw32-gcc"; rc="$arch-w64-mingw32-windres"
  command -v "$cc" >/dev/null || { echo "missing $cc: sudo apt install mingw-w64" >&2; exit 1; }
  flags="-O1 -Wall -Wl,--dynamicbase -Wl,--nxcompat"
  "$rc" -i tools/fixtures/hello.rc -O coff -o "$out/hello$tag.res.o"
  "$cc" $flags -o "$out/hello$tag.exe" tools/fixtures/hello.c "$out/hello$tag.res.o"
  "$cc" $flags -o "$out/fs$tag.exe" tools/fixtures/fs.c
  "$cc" $flags -mwindows -o "$out/gui$tag.exe" tools/fixtures/gui.c
  "$cc" $flags -shared -o "$out/exports$tag.dll" tools/fixtures/exports.c
  # x86_64 only: the bundled DXVK ships x64 DLLs only.
  if [ "$arch" = x86_64 ]; then
    "$cc" $flags -o "$out/d3d11_64.exe" tools/fixtures/d3d11.c -ld3d11 -ldxgi -ldxguid
    # The sandbox escape probe (e2e_sandbox.rs).
    "$cc" $flags -o "$out/probe64.exe" tools/fixtures/probe.c -lws2_32
  fi
  rm -f "$out/hello$tag.res.o"
done

command -v wixl >/dev/null || { echo "missing wixl: sudo apt install msitools wixl" >&2; exit 1; }
wixl -o "$out/hello.msi" tools/fixtures/hello.wxs

command -v makensis >/dev/null || { echo "missing makensis: sudo apt install nsis" >&2; exit 1; }
makensis -NOCD tools/fixtures/hello.nsi
makensis -NOCD -DNOSHORTCUT tools/fixtures/hello.nsi
makensis -NOCD tools/fixtures/dep-installer.nsi
for f in hello-nsis.exe hello-nsis-noshortcut.exe dep-installer.exe; do
  grep -qa NullsoftInst "$out/$f" || {
    echo "$f is missing the NullsoftInst marker" >&2
    exit 1
  }
done

ls -l "$out"
