#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./install.sh

# Both file execution and curl | bash must enter main; sourcing above must not.
file_help=$(bash ./install.sh --help)
stdin_help=$(bash -s -- --help < ./install.sh)
[[ -n $file_help && $stdin_help == "$file_help" ]]

for value in 1 80 443 8765 65535 0080; do valid_port "$value" || exit 1; done
for value in 0 65536 -1 abc '80;id' '1 2' 999999999; do
    if valid_port "$value"; then printf 'Invalid port accepted: %s\n' "$value"; exit 1; fi
done
for value in localhost panel.example.com 192.0.2.1; do valid_host "$value" || exit 1; done
for value in 'https://example.com' 'example.com:80' "x\$(id)" 'x..y' 'bad host'; do
    if valid_host "$value"; then exit 1; fi
done
[[ $(architecture x86_64) == amd64 && $(architecture aarch64) == arm64 ]]
if architecture i386; then exit 1; fi
valid_version v0.1.0
if valid_version '../main'; then exit 1; fi
valid_username admin-1
if valid_username 'admin;id'; then exit 1; fi
for value in panel.example.com xn--example.test; do valid_domain "$value" || exit 1; done
for value in localhost 1.1.1.1 'https://panel.example.com' '-bad.example.com' 'bad-.example.com'; do
    if valid_domain "$value"; then exit 1; fi
done

for value in 1.1.1.1 8.8.8.8; do valid_public_ipv4 "$value" || exit 1; done
for value in localhost LOCALHOST 192.168.1.1 'https://panel.example.com'; do
    if valid_public_host "$value"; then exit 1; fi
done
for value in '' localhost 256.1.1.1 01.2.3.4 0.0.0.0 127.0.0.1 10.1.2.3 172.16.0.1 192.168.1.1 169.254.1.1 100.64.0.1 198.18.0.1 192.0.2.1 224.0.0.1 '<html>'; do
    if valid_public_ipv4 "$value"; then printf 'Invalid public IPv4 accepted: %s\n' "$value"; exit 1; fi
done
# Never source generated configuration as shell code.
CONFIG_DIR=$(mktemp -d)
trap 'rm -rf -- "$CONFIG_DIR"' EXIT
printf '%s\n' 'TG_RELAY_LISTEN=127.0.0.1:9999' 'TG_RELAY_ADMIN_HOST=localhost' 'TG_RELAY_SECURE_COOKIE=false' "UNRECOGNIZED=\$(exit 66)" > "$CONFIG_DIR/panel.conf"
read_configuration
[[ $LISTEN == 127.0.0.1:9999 && $ADMIN_HOST == localhost && $SECURE_COOKIE == false ]]

# Check checksum failure stops installation before any system changes.
WORK_DIR=$CONFIG_DIR
printf payload > "$WORK_DIR/test.tar.gz"
(cd "$WORK_DIR" && sha256sum test.tar.gz > SHA256SUMS)
verify_archive test.tar.gz
printf tampered > "$WORK_DIR/test.tar.gz"
if (verify_archive test.tar.gz) >/dev/null 2>&1; then exit 1; fi
if command -v openssl >/dev/null; then
    MSYS2_ARG_CONV_EXCL=/CN= openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$CONFIG_DIR/key.pem" -out "$CONFIG_DIR/cert.pem" -days 1 -subj /CN=panel.example.com -addext subjectAltName=DNS:panel.example.com 2>/dev/null
    validate_certificate "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem" panel.example.com
    if validate_certificate "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem" wrong.example.com; then printf 'Wrong certificate domain accepted.\n'; exit 1; fi
fi
(
    # Network responses are fixtures; these checks must not contact an IP service.
    mock_ip_response=
    curl() { [[ -n $mock_ip_response ]] || return 1; printf '%s' "$mock_ip_response"; }
    SSH_CONNECTION='192.0.2.1 12345 8.8.8.8 22'
    [[ $(detect_public_ipv4) == 8.8.8.8 ]]
    SSH_CONNECTION='192.0.2.1 12345 192.168.1.2 22'
    mock_ip_response=1.1.1.1
    [[ $(detect_public_ipv4) == 1.1.1.1 ]]
    unset SSH_CONNECTION
    [[ $(detect_public_ipv4) == 1.1.1.1 ]]
    mock_ip_response='<html>unexpected response</html>'
    if detect_public_ipv4; then exit 1; fi
    mock_ip_response=10.0.0.1
    if detect_public_ipv4; then exit 1; fi

    # Replace terminal I/O only; exercise the real configuration and validation.
    ask() {
        local answer
        IFS= read -r answer
        printf -v "$1" '%s' "${answer:-$3}"
    }
    mock_ip_response=1.1.1.1
    LISTEN=127.0.0.1:8765 ADMIN_HOST=localhost SECURE_COOKIE=false
    configure_panel 3>/dev/null <<'INPUT'

2

INPUT
    [[ $ADMIN_HOST == 1.1.1.1 && $LISTEN == 0.0.0.0:8765 && $SECURE_COOKIE == false ]]
    ADMIN_HOST=localhost
    configure_panel 3>/dev/null <<'INPUT'
9000
2
panel.example.com
INPUT
    [[ $ADMIN_HOST == panel.example.com && $LISTEN == 0.0.0.0:9000 ]]
    mock_ip_response=
    configure_panel 3>/dev/null <<'INPUT'

2

INPUT
    [[ $ADMIN_HOST == panel.example.com ]]
    ADMIN_HOST=localhost
    configure_panel 3>/dev/null <<'INPUT'

2

localhost
http://panel.example.com:9000
panel.example.com
INPUT
    [[ $ADMIN_HOST == panel.example.com ]]
)
printf 'Installer input, config parsing and checksum checks passed.\n'
