#!/bin/sh
# Builds tests/fixtures/build/hello-managed.exe (gitignored) from tools/fixtures/hello-managed.cs with Wine Mono's
# own C# compiler, inside a scratch Wine prefix that is deleted afterwards. Needs Wine 10.0, curl and the network.
#
#   tools/build-managed-fixture.sh [--force]
#
# The Wine Mono MSI's url, size and sha256 are read from the `wine-mono` entry of crates/deps/packages.toml (the
# one source of truth); the download is refused unless both match. MONO_MSI=<path> uses a local copy instead of
# downloading it, verified the same way. Skips when the exe exists, unless --force.
set -eu
cd "$(dirname "$0")/.."
out=tests/fixtures/build/hello-managed.exe

force=0
case "${1:-}" in
  --force) force=1 ;;
  "") ;;
  *) echo "usage: $0 [--force]" >&2; exit 2 ;;
esac
if [ -f "$out" ] && [ "$force" = 0 ]; then
  echo "$out exists (use --force to rebuild)"
  exit 0
fi

command -v wine >/dev/null || { echo "missing wine: sudo apt install wine (Wine 10.0 expects Wine Mono 9.4.0)" >&2; exit 1; }
# `wineserver` is often not on PATH (Ubuntu): the same places crates/backend-wine/src/discover.rs looks.
wineserver=$(command -v wineserver || true)
for c in /usr/lib/x86_64-linux-gnu/wine/wineserver /usr/lib64/wine/wineserver /usr/lib/wine/wineserver \
  /usr/lib/wine/wineserver64 /opt/wine-stable/bin/wineserver /opt/wine-staging/bin/wineserver \
  /opt/wine-devel/bin/wineserver; do
  [ -n "$wineserver" ] && break
  [ -x "$c" ] && wineserver=$c
done
[ -n "$wineserver" ] || { echo "missing wineserver (part of the wine package)" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "missing sha256sum (coreutils)" >&2; exit 1; }

# The `wine-mono` entry: from its `id` line to the next `[[package]]`.
field() {
  awk '/^\[\[package\]\]/ { p = 0 } /^id = "wine-mono"$/ { p = 1 } p' crates/deps/packages.toml |
    sed -n "s/^$1 = \"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p"
}
url=$(field url); sha=$(field sha256); size=$(field size)
[ -n "$url" ] && [ -n "$sha" ] && [ -n "$size" ] || {
  echo "cannot read the wine-mono url/sha256/size from crates/deps/packages.toml" >&2
  exit 1
}

scratch=$(mktemp -d)
cleanup() {
  WINEPREFIX="$scratch/prefix" "$wineserver" -k 2>/dev/null || true
  rm -rf "$scratch"
}
# A signal exits (non-zero), and the exit runs the cleanup.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

msi="$scratch/wine-mono.msi"
if [ -n "${MONO_MSI:-}" ]; then
  cp "$MONO_MSI" "$msi"
else
  command -v curl >/dev/null || { echo "missing curl: sudo apt install curl" >&2; exit 1; }
  echo "downloading $url"
  # HTTPS only; a stalled link (under 10 kB/s for 60 s) fails, a slow but live one is not cut off.
  curl -fsSL --proto =https --tlsv1.2 --speed-limit 10000 --speed-time 60 -o "$msi" "$url" || {
    echo "cannot download $url (this script needs the network)" >&2
    exit 1
  }
fi
got_size=$(stat -c %s "$msi")
got_sha=$(sha256sum "$msi" | cut -d' ' -f1)
[ "$got_size" = "$size" ] && [ "$got_sha" = "$sha" ] || {
  echo "the MSI does not match the manifest: size $got_size (want $size), sha256 $got_sha (want $sha)" >&2
  exit 1
}

export WINEPREFIX="$scratch/prefix" WINEDEBUG=-all
# Installed with mscoree disabled (as the runtime's installer sessions do), so Wine's own Mono prompt cannot run.
WINEDLLOVERRIDES='winemenubuilder.exe=d;mscoree=d;mshtml=d' wine msiexec /i "$msi" /qn
drive_c="$WINEPREFIX/drive_c"
[ -f "$drive_c/windows/mono/mono-2.0/bin/libmono-2.0-x86_64.dll" ] || {
  echo "Wine Mono did not install (no libmono-2.0-x86_64.dll in the scratch prefix)" >&2
  exit 1
}
cp tools/fixtures/hello-managed.cs "$drive_c/hello-managed.cs"
# The compiler is itself a managed program: mscoree enabled.
WINEDLLOVERRIDES='winemenubuilder.exe=d;mshtml=d' wine 'C:\windows\mono\mono-2.0\lib\mono\4.5\csc.exe' \
  /nologo /out:'C:\hello-managed.exe' 'C:\hello-managed.cs'
"$wineserver" -w
mkdir -p "$(dirname "$out")"
cp "$drive_c/hello-managed.exe" "$out"
ls -l "$out"
