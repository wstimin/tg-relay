#!/usr/bin/env bash
# Mocks are called indirectly; each subshell establishes its own configuration.
# shellcheck disable=SC2030,SC2031,SC2329
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
(
    # An existing installation must never call any settings/password prompt.
    fixture=$(mktemp -d)
    trap 'rm -rf -- "$fixture"; if [[ -n $WORK_DIR && $WORK_DIR == /tmp/tg-relay.* ]]; then rm -rf -- "$WORK_DIR"; fi' EXIT
    INSTALL_DIR=$fixture/installed DATA_DIR=$fixture/data CONFIG_DIR=$fixture/config UNIT=$fixture/main.service MENU_COMMAND=$fixture/tg
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$CONFIG_DIR" "$fixture/package"
    cat > "$fixture/package/tg-relay" <<'MOCK'
#!/usr/bin/env bash
case "$1" in -version) printf '%s' "${MOCK_VERSION:-v0.4.0}";; -admin-status) printf initialized;; -admin-username) printf retained-admin;; *) exit 1;; esac
MOCK
    chmod +x "$fixture/package/tg-relay"
    cp "$fixture/package/tg-relay" "$INSTALL_DIR/tg-relay"
    cp install.sh LICENSE.mtg THIRD_PARTY_NOTICES.md deploy/tg-relay.service deploy/tg-relay-renew.service deploy/tg-relay-renew.timer deploy/tg-relay-update.service deploy/tg-relay-update.path "$fixture/package/"
    tar -czf "$fixture/asset.tar.gz" -C "$fixture/package" .
    printf 'TG_RELAY_LISTEN=0.0.0.0:9443\nTG_RELAY_ADMIN_HOST=panel.example.com\nTG_RELAY_SECURE_COOKIE=true\nTG_RELAY_TLS_CERT=/existing/cert.pem\nTG_RELAY_TLS_KEY=/existing/key.pem\n' > "$CONFIG_DIR/panel.conf"
    before=$(sha256sum "$CONFIG_DIR/panel.conf")
    VERSION=v0.4.0
    configure_panel() { printf 'Unexpected panel prompt\n' >&2; exit 1; }
    read_admin() { printf 'Unexpected credential prompt\n' >&2; exit 1; }
    ask() { printf 'Unexpected prompt\n' >&2; exit 1; }
    write_configuration() { printf 'Unexpected config rewrite\n' >&2; exit 1; }
    certificate_deploy() { exit 1; }
    configure_renewal() { exit 1; }
    systemctl() { return 0; }
    ss() { return 0; }
    id() { return 0; }
    install() { return 0; }
    ln() { return 0; }
    chown() { return 0; }
    wait_panel() { return 0; }
    show_panel() { return 0; }
    download() {
        local output='' url=${!#}
        while (($#)); do if [[ $1 == --output ]]; then output=$2; shift 2; else shift; fi; done
        if [[ $url == */releases/latest\?* ]]; then printf 'https://github.com/wstimin/tg-relay/releases/tag/%s' "$MOCK_VERSION"; return; fi
        if [[ $url == */SHA256SUMS ]]; then
            local sum
            sum=$(sha256sum "$fixture/asset.tar.gz"); sum=${sum%% *}
            printf '%s  tg-relay-linux-%s.tar.gz\n' "$sum" "$(architecture "$(uname -m)")" > "$output"
        else cp "$fixture/asset.tar.gz" "$output"; fi
    }
    # Package paths match real release archives (without a leading ./).
    tar -czf "$fixture/asset.tar.gz" -C "$fixture/package" tg-relay tg-relay.service install.sh tg-relay-renew.service tg-relay-renew.timer tg-relay-update.service tg-relay-update.path LICENSE.mtg THIRD_PARTY_NOTICES.md
    install_release
    [[ $(sha256sum "$CONFIG_DIR/panel.conf") == "$before" && $ADMIN_USER == retained-admin && $LISTEN == 0.0.0.0:9443 && $TLS_CERT == /existing/cert.pem ]]
    VERSION=
    export MOCK_VERSION=v0.4.1
    install_release
    [[ $(cat "$INSTALL_DIR/version") == v0.4.1 && -z $VERSION ]]
    MOCK_VERSION=v0.4.2
    install_release
    [[ $(cat "$INSTALL_DIR/version") == v0.4.2 && -z $VERSION ]]
    # Refuse a mismatched binary before changing installed files or service state.
    VERSION=v0.9.9
    if (install_release) >/dev/null 2>&1; then printf 'Wrong binary version accepted\n'; exit 1; fi
)
printf 'Installer input, config parsing and checksum checks passed.\n'
