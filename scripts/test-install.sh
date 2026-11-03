#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./install.sh

for value in 1 80 443 8765 65535 0080; do valid_port "$value" || exit 1; done
for value in 0 65536 -1 abc '80;id' '1 2' 999999999; do
    if valid_port "$value"; then printf 'Invalid port accepted: %s\n' "$value"; exit 1; fi
done
for value in localhost panel.example.com 192.0.2.1; do valid_host "$value" || exit 1; done
for value in 'https://example.com' 'example.com:80' 'x$(id)' 'x..y' 'bad host'; do
    if valid_host "$value"; then exit 1; fi
done
[[ $(architecture x86_64) == amd64 && $(architecture aarch64) == arm64 ]]
if architecture i386; then exit 1; fi
valid_version v0.1.0
if valid_version '../main'; then exit 1; fi
valid_username admin-1
if valid_username 'admin;id'; then exit 1; fi

# Never source generated configuration as shell code.
CONFIG_DIR=$(mktemp -d)
trap 'rm -rf -- "$CONFIG_DIR"' EXIT
printf '%s\n' 'TG_RELAY_LISTEN=127.0.0.1:9999' 'TG_RELAY_ADMIN_HOST=localhost' 'TG_RELAY_SECURE_COOKIE=false' 'UNRECOGNIZED=$(exit 66)' > "$CONFIG_DIR/panel.conf"
read_configuration
[[ $LISTEN == 127.0.0.1:9999 && $ADMIN_HOST == localhost && $SECURE_COOKIE == false ]]

# Check checksum failure stops installation before any system changes.
WORK_DIR=$CONFIG_DIR
printf payload > "$WORK_DIR/test.tar.gz"
(cd "$WORK_DIR" && sha256sum test.tar.gz > SHA256SUMS)
verify_archive test.tar.gz
printf tampered > "$WORK_DIR/test.tar.gz"
if (verify_archive test.tar.gz) >/dev/null 2>&1; then exit 1; fi
printf 'Installer input, config parsing and checksum checks passed.\n'
