#!/usr/bin/env bash
# Buduje pakiet instalacyjny: proces RDP jako sidecar Tauri (nazwa z triplem docelowym), frontend i instalatory.
# Użycie: scripts/build-release.sh [argumenty dla `tauri build`, np. --bundles deb]
# Zmienna PROFILE=debug przyspiesza próbne budowanie (domyślnie release).
set -euo pipefail
cd "$(dirname "$0")/.."

profile="${PROFILE:-release}"
triple="$(rustc -vV | sed -n 's/^host: //p')"
ext=""
case "$triple" in *windows*) ext=".exe" ;; esac

if [ "$profile" = "release" ]; then
  cargo build --release --manifest-path tools/rdp/Cargo.toml -p rdp-worker
else
  cargo build --manifest-path tools/rdp/Cargo.toml -p rdp-worker
fi

mkdir -p crates/app/binaries
cp "tools/rdp/target/$profile/rdp-worker$ext" "crates/app/binaries/multiremotemanager-rdp-worker-$triple$ext"

pnpm --dir app/ui install --frozen-lockfile
pnpm --dir app/ui build
cd crates/app
../../app/ui/node_modules/.bin/tauri build "$@"
