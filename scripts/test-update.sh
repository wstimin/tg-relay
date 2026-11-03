#!/usr/bin/env bash
# Disposable GitHub Linux runner only: exercises the real root/systemd update path.
set -Eeuo pipefail
[[ ${TG_RELAY_DISPOSABLE_RUNNER:-} == yes && $EUID == 0 ]] || { printf 'Requires an explicitly disposable root runner.\n' >&2; exit 1; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
target=${1:?release tag required}
[[ $target =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
fixture=$(mktemp -d)
menu_pid=
cleanup() {
    if [[ -n $menu_pid ]]; then kill "$menu_pid" >/dev/null 2>&1 || true; wait "$menu_pid" 2>/dev/null || true; fi
    systemctl disable --now tg-relay-update.path >/dev/null 2>&1 || true
    systemctl stop tg-relay.service || true
    rm -rf -- "$fixture"
}
trap cleanup EXIT
mkdir -p /opt/tg-relay /etc/tg-relay /var/lib/tg-relay
id tg-relay >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/tg-relay --shell /usr/sbin/nologin tg-relay
go build -trimpath -ldflags '-X main.buildVersion=v0.0.1' -o /opt/tg-relay/tg-relay .
install -m 0755 install.sh /opt/tg-relay/manage.sh
install -m 0644 LICENSE.mtg THIRD_PARTY_NOTICES.md /opt/tg-relay/
install -m 0644 deploy/tg-relay*.service deploy/tg-relay*.timer deploy/tg-relay*.path /etc/systemd/system/
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /etc/tg-relay/key.pem -out /etc/tg-relay/cert.pem -days 1 -subj /CN=panel.example.com -addext subjectAltName=DNS:panel.example.com >/dev/null 2>&1
chown root:tg-relay /etc/tg-relay/key.pem
chmod 0640 /etc/tg-relay/key.pem
chmod 0644 /etc/tg-relay/cert.pem
printf 'TG_RELAY_LISTEN=127.0.0.1:18765\nTG_RELAY_ADMIN_HOST=panel.example.com\nTG_RELAY_SECURE_COOKIE=true\nTG_RELAY_TLS_CERT=/etc/tg-relay/cert.pem\nTG_RELAY_TLS_KEY=/etc/tg-relay/key.pem\n' > /etc/tg-relay/panel.conf
curl() { command curl --noproxy '*' --cacert /etc/tg-relay/cert.pem --resolve panel.example.com:18765:127.0.0.1 "$@"; }
cp /etc/tg-relay/panel.conf "$fixture/panel.conf"
sha256sum /etc/tg-relay/cert.pem /etc/tg-relay/key.pem > "$fixture/cert-sha256"
printf 123456 | /opt/tg-relay/tg-relay -init-admin -admin-user update-test -data /var/lib/tg-relay
chown -R tg-relay:tg-relay /var/lib/tg-relay
systemctl daemon-reload
systemctl enable --now tg-relay-update.path
systemctl start tg-relay.service
for _ in {1..30}; do if curl -fsS https://panel.example.com:18765/api/auth > "$fixture/auth.json"; then break; fi; sleep 1; done
curl -fsS -c "$fixture/cookies" -H 'Content-Type: application/json' -d '{"username":"update-test","password":"123456"}' https://panel.example.com:18765/api/login
curl -fsS -b "$fixture/cookies" -H 'Content-Type: application/json' -d '{"name":"preserved","listenIP":"127.0.0.1","port":18443,"publicHost":"relay.example.com","tlsDomain":"www.apple.com","enabled":true,"initialRoute":{"direct":true,"outboundID":""}}' https://panel.example.com:18765/api/inbounds
curl -fsS -b "$fixture/cookies" -H 'Content-Type: application/json' -d '{"name":"preserved-user","enabled":true,"quotaBytes":10000}' https://panel.example.com:18765/api/users > "$fixture/user.json"
curl -fsS -b "$fixture/cookies" https://panel.example.com:18765/api/backup > "$fixture/before.json"
python3 - "$fixture/before.json" > "$fixture/credential.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))['config']
print(json.dumps(dict(inboundID=c['inbounds'][0]['id'],userID=c['users'][0]['id'],enabled=True)))
PY
curl -fsS -b "$fixture/cookies" -H 'Content-Type: application/json' --data-binary "@$fixture/credential.json" https://panel.example.com:18765/api/credentials
curl -fsS -b "$fixture/cookies" https://panel.example.com:18765/api/backup > "$fixture/before.json"
curl -fsS -b "$fixture/cookies" -X POST https://panel.example.com:18765/api/update/check > "$fixture/check.json"
python3 - "$fixture/check.json" "$target" <<'PY'
import json,sys
u=json.load(open(sys.argv[1]));assert u['latest']==sys.argv[2] and u['available'] and u['supported'],u
PY
# Keep the actual interactive tg menu idle while the panel update runs.
# The menu must not hold the update lock while it waits for user input.
mkfifo "$fixture/menu-input"
exec 8<>"$fixture/menu-input"
script --quiet --return --command /opt/tg-relay/manage.sh /dev/null <&8 > "$fixture/menu.log" 2>&1 &
menu_pid=$!
for _ in {1..50}; do if [[ $(cat "$fixture/menu.log") == *选择操作* ]]; then break; fi; sleep 0.1; done
[[ $(cat "$fixture/menu.log") == *选择操作* ]] || { cat "$fixture/menu.log"; exit 1; }
flock -n /run/tg-relay-install.lock true || { printf 'Idle tg menu blocks panel updates.\n'; exit 1; }
curl -fsS -b "$fixture/cookies" -H 'Content-Type: application/json' -d "{\"version\":\"$target\",\"confirm\":true}" https://panel.example.com:18765/api/update
for _ in {1..240}; do
    if [[ -f /var/lib/tg-relay/update-status.json ]]; then
        phase=$(python3 -c 'import json;print(json.load(open("/var/lib/tg-relay/update-status.json"))["phase"])')
        if [[ $phase == complete ]]; then break; fi
        if [[ $phase == failed ]]; then cat /var/lib/tg-relay/update-status.json; exit 1; fi
    fi
    sleep 1
done
[[ ${phase:-} == complete ]]
kill -0 "$menu_pid"
[[ $(/opt/tg-relay/tg-relay -version) == "$target" && $(cat /opt/tg-relay/version) == "$target" ]]
cmp /etc/tg-relay/panel.conf "$fixture/panel.conf"
sha256sum -c "$fixture/cert-sha256"
printf 123456 | /opt/tg-relay/tg-relay -verify-admin -admin-user update-test -data /var/lib/tg-relay
[[ $(curl -s -o /dev/null -w '%{http_code}' -b "$fixture/cookies" https://panel.example.com:18765/api/state) == 401 ]]
curl -fsS -c "$fixture/cookies" -H 'Content-Type: application/json' -d '{"username":"update-test","password":"123456"}' https://panel.example.com:18765/api/login
curl -fsS -b "$fixture/cookies" https://panel.example.com:18765/api/backup > "$fixture/after.json"
python3 - "$fixture/before.json" "$fixture/after.json" <<'PY'
import json,sys
a,b=[json.load(open(p)) for p in sys.argv[1:]]
assert a['config']==b['config'] and a['usage']==b['usage'],'Configuration, secrets or usage changed'
PY
systemctl is-active --quiet tg-relay.service
printf 'Real release update via API/systemd passed; port, account, credentials, routes and usage preserved.\n'
