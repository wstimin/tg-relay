#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY=wstimin/tg-relay
INSTALL_DIR=/opt/tg-relay
DATA_DIR=/var/lib/tg-relay
CONFIG_DIR=/etc/tg-relay
UNIT=/etc/systemd/system/tg-relay.service
MENU_COMMAND=/usr/local/bin/tg
ACME_HOME=/etc/tg-relay/acme
WORK_DIR=
RESTART_ON_ERROR=0
VERSION=
PENDING_CERT_DOMAIN=

die() { printf '错误：%s\n' "$*" >&2; exit 1; }
valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
valid_host() {
    [[ ${#1} -le 253 && $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && $1 != *..* ]]
}
valid_public_ipv4() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local a b c d octet
    IFS=. read -r a b c d <<< "$1"
    for octet in "$a" "$b" "$c" "$d"; do
        [[ $octet == 0 || $octet != 0* ]] && ((10#$octet <= 255)) || return 1
    done
    ((a > 0 && a < 224 && a != 10 && a != 127 &&
        !(a == 100 && b >= 64 && b <= 127) &&
        !(a == 172 && b >= 16 && b <= 31))) || return 1
    case "$a.$b" in 169.254|192.168|198.18|198.19) return 1;; esac
    case "$a.$b.$c" in 192.0.0|192.0.2|192.88.99|198.51.100|203.0.113) return 1;; esac
}
valid_public_host() {
    valid_host "$1" && [[ ${1,,} != localhost ]] || return 1
    if [[ $1 =~ ^[0-9.]+$ ]]; then valid_public_ipv4 "$1"; fi
}
detect_public_ipv4() {
    local detected
    local -a ssh_fields
    read -r -a ssh_fields <<< "${SSH_CONNECTION:-}"
    if valid_public_ipv4 "${ssh_fields[2]:-}"; then
        printf '%s' "${ssh_fields[2]}"
        return
    fi
    detected=$(curl --ipv4 --fail --silent --noproxy '*' --proto '=https' --connect-timeout 2 --max-time 4 https://api.ipify.org) || return 1
    valid_public_ipv4 "$detected" || return 1
    printf '%s' "$detected"
}
valid_username() { [[ $1 =~ ^[a-zA-Z0-9_.-]{1,64}$ ]]; }
valid_version() { [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
architecture() {
    case "$1" in x86_64|amd64) printf amd64;; aarch64|arm64) printf arm64;; *) return 1;; esac
}
download() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2 "$@"; }
ask() {
    local prompt_reply
    printf '%s [%s]：' "$2" "$3" >&3
    IFS= read -r prompt_reply <&3 || die '输入中断'
    printf -v "$1" '%s' "${prompt_reply:-$3}"
}
cleanup() {
    local code=$?
    trap - EXIT
    unset ADMIN_PASSWORD PASSWORD_CONFIRM
    if ((code != 0 && RESTART_ON_ERROR)); then systemctl start tg-relay.service || true; fi
    if [[ -n $WORK_DIR && $WORK_DIR == /tmp/tg-relay.* && -d $WORK_DIR ]]; then rm -rf -- "$WORK_DIR"; fi
    exit "$code"
}
safe_paths() {
    local path
    for path in "$INSTALL_DIR" "$DATA_DIR" "$CONFIG_DIR" "$UNIT" "$ACME_HOME" "$CONFIG_DIR/tls" "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem"; do
        [[ ! -L $path ]] || die "拒绝操作符号链接：$path"
    done
    if [[ -e $MENU_COMMAND || -L $MENU_COMMAND ]]; then
        [[ -L $MENU_COMMAND && $(readlink "$MENU_COMMAND") == "$INSTALL_DIR/manage.sh" ]] || die "$MENU_COMMAND 已被其他程序使用，请先处理命令冲突"
    fi
}
verify_archive() {
    local asset=$1 hash
    hash=$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1 }' "$WORK_DIR/SHA256SUMS")
    [[ $hash =~ ^[a-fA-F0-9]{64}$ ]] || die '发布校验文件缺失或格式错误'
    printf '%s  %s\n' "$hash" "$asset" | (cd "$WORK_DIR" && sha256sum --check --status) || die '下载文件 SHA256 校验失败'
}
read_configuration() {
    local key value
    LISTEN=127.0.0.1:8765
    ADMIN_HOST=localhost
    SECURE_COOKIE=false
    TLS_CERT=
    TLS_KEY=
    if [[ -f $CONFIG_DIR/panel.conf ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                TG_RELAY_LISTEN) LISTEN=$value;;
                TG_RELAY_ADMIN_HOST) ADMIN_HOST=$value;;
                TG_RELAY_SECURE_COOKIE) SECURE_COOKIE=$value;;
                TG_RELAY_TLS_CERT) TLS_CERT=$value;;
                TG_RELAY_TLS_KEY) TLS_KEY=$value;;
            esac
        done < "$CONFIG_DIR/panel.conf"
    fi
}
configure_panel() {
    local default_port=${LISTEN##*:} mode=${1:-1} bind_ip
    if [[ ${1:-} == 3 && -z $TLS_CERT ]]; then default_port=443; fi
    valid_port "$default_port" || default_port=8765
    ask PANEL_PORT '面板访问端口（与 TG 入站端口独立）' "$default_port"
    valid_port "$PANEL_PORT" || die '端口必须是 1–65535'
    PANEL_PORT=$((10#$PANEL_PORT))
    if [[ -z ${1:-} ]]; then
        printf '\n1) 本机访问 / SSH 隧道\n2) 公网 HTTP（未加密）\n3) 域名 HTTPS（自动申请证书）\n4) 已有 HTTPS 反向代理\n' >&3
        case "$LISTEN:$SECURE_COOKIE:$TLS_CERT" in 0.0.0.0:*:false:*) mode=2;; *:true:) mode=4;; *:true:*) mode=3;; esac
        ask mode '面板访问方式' "$mode"
    fi
    SECURE_COOKIE=false
    if [[ $mode != 3 ]]; then TLS_CERT=; TLS_KEY=; fi
    case "$mode" in
        1) bind_ip=127.0.0.1; ADMIN_HOST=localhost;;
        2)
            bind_ip=0.0.0.0
            if ! valid_public_host "$ADMIN_HOST"; then
                printf '正在识别服务器公网 IPv4…\n' >&3
                if ADMIN_HOST=$(detect_public_ipv4); then
                    printf '识别到：%s；回车使用，也可修改为实际访问地址。\n' "$ADMIN_HOST" >&3
                else
                    ADMIN_HOST=
                    printf '未能自动识别公网 IPv4，请手动填写公网 IPv4 或域名。\n' >&3
                fi
            fi
            while true; do
                ask ADMIN_HOST '访问面板使用的服务器 IPv4 / 域名（不带协议和端口）' "$ADMIN_HOST"
                if valid_public_host "$ADMIN_HOST"; then break; fi
                printf '地址无效，请填写公网 IPv4 或域名；不能使用 localhost、内网地址或带协议和端口的 URL。\n' >&3
            done;;
        3) [[ $PANEL_PORT != 80 ]] || die 'TCP 80 需留给证书验证，请选择 443 或其他 HTTPS 端口'; bind_ip=0.0.0.0; issue_certificate; SECURE_COOKIE=true;;
        4) bind_ip=127.0.0.1; ask ADMIN_HOST '已有 HTTPS 面板域名（不带协议和端口）' "$ADMIN_HOST"; valid_domain "$ADMIN_HOST" || die '请填写 HTTPS 域名'; SECURE_COOKIE=true;;
        *) die '访问方式必须为 1、2、3 或 4';;
    esac
    valid_host "$ADMIN_HOST" || die '主机名无效；当前安装器支持 IPv4 或 ASCII 域名'
    LISTEN="$bind_ip:$PANEL_PORT"
}
read_admin() {
    ask ADMIN_USER '管理员用户名（字母、数字、下划线、点或连字符）' "${ADMIN_USER:-admin}"
    valid_username "$ADMIN_USER" || die '用户名必须为 1–64 个允许的字符'
    while true; do
        printf '管理员密码（6–256 字节，隐藏输入）：' >&3
        IFS= read -r -s ADMIN_PASSWORD <&3 || die '密码输入中断'
        printf '\n再次输入密码：' >&3
        IFS= read -r -s PASSWORD_CONFIRM <&3 || die '密码输入中断'
        printf '\n' >&3
        if [[ ${#ADMIN_PASSWORD} -ge 6 && ${#ADMIN_PASSWORD} -le 256 && $ADMIN_PASSWORD == "$PASSWORD_CONFIRM" ]]; then break; fi
        printf '长度不符合要求或两次密码不一致，请重试。\n' >&3
    done
    unset PASSWORD_CONFIRM
}
valid_domain() {
    valid_host "$1" && [[ $1 == *.* && ! $1 =~ ^[0-9.]+$ ]] || return 1
    local label
    local -a labels
    IFS=. read -r -a labels <<< "$1"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && $label != -* && $label != *- ]] || return 1
    done
}
write_configuration() {
    printf 'TG_RELAY_LISTEN=%s\nTG_RELAY_ADMIN_HOST=%s\nTG_RELAY_SECURE_COOKIE=%s\nTG_RELAY_TLS_CERT=%s\nTG_RELAY_TLS_KEY=%s\n' "$LISTEN" "$ADMIN_HOST" "$SECURE_COOKIE" "$TLS_CERT" "$TLS_KEY" > "$CONFIG_DIR/panel.conf"
    chmod 0600 "$CONFIG_DIR/panel.conf"
}
require_installed() { [[ -x $INSTALL_DIR/tg-relay ]] || die '请先选择 1 安装 / 更新程序'; }
show_panel() {
    require_installed
    read_configuration
    local port=${LISTEN##*:} username
    username=$("$INSTALL_DIR/tg-relay" -admin-username -data "$DATA_DIR") || die '无法读取管理员账号，请先更新程序或初始化账号'
    printf '管理员用户名：%s\n面板端口：%s\n' "$username" "$port"
    if [[ -n $TLS_CERT ]]; then
        printf '访问：https://%s:%s\n' "$ADMIN_HOST" "$port"
    elif [[ $SECURE_COOKIE == true ]]; then
        printf '访问：https://%s （反向代理应转发到 127.0.0.1:%s）\n' "$ADMIN_HOST" "$port"
    elif [[ $LISTEN == 127.0.0.1:* ]]; then
        printf 'SSH 隧道：ssh -L %s:127.0.0.1:%s 你的SSH用户@服务器\n浏览器：http://127.0.0.1:%s\n' "$port" "$port" "$port"
    else
        printf '访问：http://%s:%s\n公网 HTTP 不加密管理密码，可在菜单中启用域名 HTTPS。\n' "$ADMIN_HOST" "$port"
    fi
    printf '请放行面板端口；TG 入站端口在面板单独配置和放行。\n'
}
wait_panel() {
    local port=${LISTEN##*:}
    for _ in {1..20}; do
        if systemctl is-active --quiet tg-relay.service; then
            if [[ -n $TLS_CERT ]]; then
                if curl --fail --silent --noproxy '*' --cacert "$TLS_CERT" --resolve "$ADMIN_HOST:$port:127.0.0.1" --connect-timeout 1 --max-time 2 "https://$ADMIN_HOST:$port/api/auth" >/dev/null; then return; fi
            elif curl --fail --silent --noproxy '*' --connect-timeout 1 --max-time 2 "http://127.0.0.1:$port/api/auth" >/dev/null; then return; fi
        fi
        sleep 1
    done
    return 1
}
reset_admin_credentials() {
    require_installed
    ADMIN_USER=$("$INSTALL_DIR/tg-relay" -admin-username -data "$DATA_DIR") || die '请先选择 1 更新程序'
    printf '当前管理员：%s；新密码保存后旧管理会话立即失效，TG 代理配置不变。\n' "$ADMIN_USER" >&3
    read_admin
    printf '%s' "$ADMIN_PASSWORD" | "$INSTALL_DIR/tg-relay" -reset-admin -admin-user "$ADMIN_USER" -data "$DATA_DIR"
    printf '%s' "$ADMIN_PASSWORD" | "$INSTALL_DIR/tg-relay" -verify-admin -admin-user "$ADMIN_USER" -data "$DATA_DIR"
    unset ADMIN_PASSWORD
    printf '账号密码已重置并校验。用户名：%s；请使用新密码登录。\n' "$ADMIN_USER"
}
change_panel() {
    require_installed
    local previous_config old_port confirm old_cert='' old_key='' old_domain=''
    previous_config=$(cat "$CONFIG_DIR/panel.conf")
    read_configuration
    if [[ -f $CONFIG_DIR/tls/cert.pem ]]; then old_cert=$(cat "$CONFIG_DIR/tls/cert.pem"); old_key=$(cat "$CONFIG_DIR/tls/key.pem"); fi
    if [[ -f $CONFIG_DIR/tls/managed-domain ]]; then old_domain=$(cat "$CONFIG_DIR/tls/managed-domain"); fi
    old_port=${LISTEN##*:}
    configure_panel "$@"
    if [[ $PANEL_PORT != "$old_port" ]]; then
        [[ -z $(ss -H -ltn "( sport = :$PANEL_PORT )") ]] || die "端口 $PANEL_PORT 已占用"
    fi
    ask confirm '应用面板监听配置需重启服务，将断开已有 TG 连接，是否继续 y/N' n
    [[ $confirm == y || $confirm == Y ]] || { printf '已取消，当前面板配置未更改。\n'; return; }
    if [[ -n $TLS_CERT ]]; then activate_certificate; certificate_deploy; fi
    write_configuration
    if ! systemctl restart tg-relay.service || ! wait_panel; then
        printf '%s\n' "$previous_config" > "$CONFIG_DIR/panel.conf"
        if [[ -n $old_cert ]]; then printf '%s\n' "$old_cert" > "$CONFIG_DIR/tls/cert.pem"; printf '%s\n' "$old_key" > "$CONFIG_DIR/tls/key.pem"; fi
        if [[ -n $old_domain ]]; then printf '%s\n' "$old_domain" > "$CONFIG_DIR/tls/managed-domain"; else rm -f -- "$CONFIG_DIR/tls/managed-domain"; fi
        systemctl restart tg-relay.service || true
        die '新面板配置未能启动，已恢复原配置；请查看日志'
    fi
    if [[ -n $TLS_CERT ]]; then configure_renewal; fi
    show_panel
}
certificate_dependencies() {
    local confirm
    if command -v openssl >/dev/null && command -v socat >/dev/null; then return; fi
    ask confirm '证书申请需要 openssl 和 socat，是否从系统软件仓库安装 y/N' y
    [[ $confirm == y || $confirm == Y ]] || die '已取消证书申请'
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y openssl socat ca-certificates
    elif command -v dnf >/dev/null; then
        dnf install -y openssl socat ca-certificates
    else
        die '请先从系统软件仓库安装 openssl、socat、ca-certificates 后重试'
    fi
}
validate_certificate() {
    local cert_hash key_hash
    openssl x509 -in "$1" -noout -checkend 0 >/dev/null && openssl x509 -in "$1" -noout -checkhost "$3" >/dev/null || return 1
    cert_hash=$(openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum) || return 1
    key_hash=$(openssl pkey -in "$2" -passin pass: -pubout -outform DER | sha256sum) || return 1
    [[ $cert_hash == "$key_hash" ]]
}
install_acme() {
    [[ -f $ACME_HOME/acme.sh ]] && return
    install -d -m 0700 "$ACME_HOME"
    if [[ -z $WORK_DIR ]]; then WORK_DIR=$(mktemp -d /tmp/tg-relay.XXXXXXXX); fi
    download --output "$WORK_DIR/acme.sh" https://raw.githubusercontent.com/acmesh-official/acme.sh/807da6498377ee5e0cf43a78091f46f12dc59a89/acme.sh
    printf '%s  %s\n' c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7 "$WORK_DIR/acme.sh" | sha256sum --check --status || die 'ACME 客户端校验失败'
    install -m 0700 "$WORK_DIR/acme.sh" "$ACME_HOME/acme.sh"
}
issue_certificate() {
    local domain='' email confirm resolved issue_status=0
    if valid_domain "$ADMIN_HOST"; then domain=$ADMIN_HOST; fi
    ask domain 'HTTPS 面板域名（请先将 DNS 指向本机）' "$domain"
    domain=${domain,,}
    valid_domain "$domain" || die '域名格式无效，请填写完整 ASCII 域名'
    certificate_dependencies
    if [[ -s $CONFIG_DIR/tls/cert.pem && -s $CONFIG_DIR/tls/key.pem ]] && validate_certificate "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem" "$domain"; then
        printf '已有匹配域名的有效证书，将继续使用。\n' >&3
    else
        resolved=$(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u) || die '域名没有可用 IPv4 解析，请检查 DNS'
        [[ -n $resolved ]] || die '域名没有可用 IPv4 解析，请检查 DNS'
        printf '域名解析到：\n%s\n请确认以上地址属于本机，公网 TCP 80 已放行；错误的 AAAA 记录也会导致申请失败。\n' "$resolved" >&3
        [[ -z $(ss -H -ltn '( sport = :80 )') ]] || die 'TCP 80 已被占用；请释放端口，或在证书菜单导入已有证书。不会停止其他服务'
        ask email '证书账户邮箱' ''
        [[ $email =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die '邮箱格式无效'
        printf "将向 Let's Encrypt 申请证书，条款：https://letsencrypt.org/repository/\n" >&3
        ask confirm '确认 DNS / 端口正确并同意 CA 条款，开始申请 y/N' n
        [[ $confirm == y || $confirm == Y ]] || die '已取消证书申请'
        install_acme
        sh "$ACME_HOME/acme.sh" --home "$ACME_HOME" --server letsencrypt --issue --standalone --keylength ec-256 -d "$domain" -m "$email" || issue_status=$?
        [[ $issue_status == 0 || $issue_status == 2 ]] || die '证书申请失败，当前面板配置未修改；请检查 DNS、80 端口和上方 ACME 提示'
        validate_certificate "$ACME_HOME/${domain}_ecc/fullchain.cer" "$ACME_HOME/${domain}_ecc/$domain.key" "$domain" || die '申请的证书未通过检查'
        ADMIN_HOST=$domain
        TLS_CERT="$ACME_HOME/${domain}_ecc/fullchain.cer"
        TLS_KEY="$ACME_HOME/${domain}_ecc/$domain.key"
        PENDING_CERT_DOMAIN=$domain
        return
    fi
    ADMIN_HOST=$domain
    TLS_CERT="$CONFIG_DIR/tls/cert.pem"
    TLS_KEY="$CONFIG_DIR/tls/key.pem"
}
activate_certificate() {
    if [[ -n $PENDING_CERT_DOMAIN ]]; then
        install -d -m 0750 "$CONFIG_DIR/tls"
        install -m 0640 "$TLS_CERT" "$CONFIG_DIR/tls/cert.pem"
        install -m 0640 "$TLS_KEY" "$CONFIG_DIR/tls/key.pem"
        printf '%s\n' "$PENDING_CERT_DOMAIN" > "$CONFIG_DIR/tls/managed-domain"
        TLS_CERT="$CONFIG_DIR/tls/cert.pem"
        TLS_KEY="$CONFIG_DIR/tls/key.pem"
        PENDING_CERT_DOMAIN=
    fi
}
certificate_deploy() {
    local domain
    domain=$ADMIN_HOST
    if [[ -f $CONFIG_DIR/tls/managed-domain ]]; then domain=$(cat "$CONFIG_DIR/tls/managed-domain"); fi
    valid_domain "$domain" || die '证书域名配置无效'
    validate_certificate "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem" "$domain" || die '证书或私钥无效，拒绝部署'
    chown root:tg-relay "$CONFIG_DIR" "$CONFIG_DIR/tls" "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem"
    chmod 0750 "$CONFIG_DIR" "$CONFIG_DIR/tls"
    chmod 0640 "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem"
}
configure_renewal() {
    local domain
    [[ -f $CONFIG_DIR/tls/managed-domain ]] || return 0
    domain=$(cat "$CONFIG_DIR/tls/managed-domain")
    valid_domain "$domain" || die '自动续期域名无效'
    sh "$ACME_HOME/acme.sh" --home "$ACME_HOME" --install-cert --ecc -d "$domain" --key-file "$CONFIG_DIR/tls/key.pem" --fullchain-file "$CONFIG_DIR/tls/cert.pem" --reloadcmd "$INSTALL_DIR/manage.sh --certificate-deploy"
    systemctl daemon-reload
    systemctl enable --now tg-relay-renew.timer
}
renew_certificate() {
    local domain renewal_status=0
    [[ -f $CONFIG_DIR/tls/managed-domain && -f $ACME_HOME/acme.sh ]] || die '没有自动申请的证书，请先从证书菜单申请'
    domain=$(cat "$CONFIG_DIR/tls/managed-domain")
    valid_domain "$domain" || die '自动续期域名无效'
    [[ -z $(ss -H -ltn '( sport = :80 )') ]] || die 'TCP 80 已占用，无法完成 HTTP-01 续期；请释放端口后重试'
    sh "$ACME_HOME/acme.sh" --home "$ACME_HOME" --renew --ecc -d "$domain" --server letsencrypt || renewal_status=$?
    [[ $renewal_status == 0 || $renewal_status == 2 ]] || return "$renewal_status"
}
import_certificate() {
    require_installed
    local cert_path key_path domain port previous_config old_port confirm old_cert='' old_key='' old_domain=''
    read_configuration
    previous_config=$(cat "$CONFIG_DIR/panel.conf")
    if [[ -f $CONFIG_DIR/tls/cert.pem ]]; then old_cert=$(cat "$CONFIG_DIR/tls/cert.pem"); old_key=$(cat "$CONFIG_DIR/tls/key.pem"); fi
    if [[ -f $CONFIG_DIR/tls/managed-domain ]]; then old_domain=$(cat "$CONFIG_DIR/tls/managed-domain"); fi
    old_port=${LISTEN##*:}
    ask domain '证书对应的面板域名' "$ADMIN_HOST"
    domain=${domain,,}
    valid_domain "$domain" || die '请填写有效域名'
    ask cert_path '服务器上完整证书链 PEM 文件绝对路径' ''
    ask key_path '服务器上无口令私钥 PEM 文件绝对路径' ''
    [[ $cert_path == /* && $key_path == /* && -f $cert_path && -f $key_path ]] || die '证书或私钥文件不存在'
    command -v openssl >/dev/null || die '请先安装 openssl'
    validate_certificate "$cert_path" "$key_path" "$domain" || die '证书已过期、域名不匹配或私钥不匹配'
    ask port 'HTTPS 面板端口' 443
    valid_port "$port" || die '端口必须为 1–65535'
    port=$((10#$port))
    if [[ $port != "$old_port" ]]; then [[ -z $(ss -H -ltn "( sport = :$port )") ]] || die '端口已占用'; fi
    ask confirm '启用 HTTPS 需重启服务，已有 TG 连接会断开，继续 y/N' n
    [[ $confirm == y || $confirm == Y ]] || return 0
    install -d -m 0750 "$CONFIG_DIR/tls"
    # Read both files before replacing them, including when importing our own current paths.
    local cert_content key_content
    cert_content=$(cat "$cert_path")
    key_content=$(cat "$key_path")
    printf '%s\n' "$cert_content" > "$CONFIG_DIR/tls/cert.pem"
    printf '%s\n' "$key_content" > "$CONFIG_DIR/tls/key.pem"
    rm -f -- "$CONFIG_DIR/tls/managed-domain"
    ADMIN_HOST=$domain TLS_CERT="$CONFIG_DIR/tls/cert.pem" TLS_KEY="$CONFIG_DIR/tls/key.pem" SECURE_COOKIE=true LISTEN="0.0.0.0:$port"
    write_configuration
    certificate_deploy
    if ! systemctl restart tg-relay.service || ! wait_panel; then
        printf '%s\n' "$previous_config" > "$CONFIG_DIR/panel.conf"
        if [[ -n $old_cert ]]; then printf '%s\n' "$old_cert" > "$CONFIG_DIR/tls/cert.pem"; printf '%s\n' "$old_key" > "$CONFIG_DIR/tls/key.pem"; fi
        if [[ -n $old_domain ]]; then printf '%s\n' "$old_domain" > "$CONFIG_DIR/tls/managed-domain"; fi
        systemctl restart tg-relay.service || true
        die 'HTTPS 未能启动，已恢复原面板配置；请查看日志'
    fi
    systemctl disable --now tg-relay-renew.timer || true
    show_panel
}
certificate_menu() {
    local choice
    printf '\n证书管理\n1) 配置域名、申请证书并启用 HTTPS\n2) 导入已有证书并启用 HTTPS\n3) 检查并续期证书\n4) 查看证书和自动续期状态\n0) 返回\n' >&3
    ask choice '选择操作' 0
    case "$choice" in
        1) change_panel 3;;
        2) import_certificate;;
        3) renew_certificate;;
        4) openssl x509 -in "$CONFIG_DIR/tls/cert.pem" -noout -subject -issuer -dates; systemctl status tg-relay-renew.timer --no-pager || true;;
        0) return;;
        *) die '无效操作';;
    esac
}
install_release() {
    local arch asset release_url status active=0 admin_action='' keep_admin
    arch=$(architecture "$(uname -m)") || die '仅支持 Linux amd64 / arm64'
    if [[ -z $VERSION ]]; then
        release_url=$(download --output /dev/null --write-out '%{url_effective}' "https://github.com/$REPOSITORY/releases/latest")
        VERSION=${release_url##*/}
    fi
    valid_version "$VERSION" || die '未找到正式发布版本，或版本格式不是 vX.Y.Z'
    asset="tg-relay-linux-$arch.tar.gz"
    WORK_DIR=$(mktemp -d /tmp/tg-relay.XXXXXXXX)
    printf '下载 %s / %s …\n' "$VERSION" "$arch"
    download --output "$WORK_DIR/$asset" "https://github.com/$REPOSITORY/releases/download/$VERSION/$asset"
    download --output "$WORK_DIR/SHA256SUMS" "https://github.com/$REPOSITORY/releases/download/$VERSION/SHA256SUMS"
    verify_archive "$asset"
    tar --extract --gzip --file "$WORK_DIR/$asset" --directory "$WORK_DIR" --no-same-owner tg-relay tg-relay.service install.sh tg-relay-renew.service tg-relay-renew.timer LICENSE.mtg THIRD_PARTY_NOTICES.md
    [[ -f $WORK_DIR/tg-relay && ! -L $WORK_DIR/tg-relay && -f $WORK_DIR/tg-relay.service && ! -L $WORK_DIR/tg-relay.service ]] || die '发布包内容无效'
    chmod 0755 "$WORK_DIR/tg-relay"
    read_configuration
    configure_panel
    install -d -m 0700 "$DATA_DIR"
    install -d -m 0750 "$CONFIG_DIR"
    status=$("$WORK_DIR/tg-relay" -admin-status -data "$DATA_DIR")
    [[ $status == initialized || $status == uninitialized ]] || die '无法读取管理员状态'
    ADMIN_USER=
    if [[ $status == uninitialized ]]; then
        admin_action=-init-admin
        read_admin
    else
        ADMIN_USER=$("$WORK_DIR/tg-relay" -admin-username -data "$DATA_DIR")
        printf '当前管理员用户名：%s\n' "$ADMIN_USER" >&3
        ask keep_admin '管理员账号：1 保留，2 重新设置账号和密码' 1
        case "$keep_admin" in 1) ;; 2) admin_action=-reset-admin; read_admin;; *) die '请选择 1 或 2';; esac
    fi
    systemctl is-active --quiet tg-relay.service && active=1
    if ((active)); then systemctl stop tg-relay.service; RESTART_ON_ERROR=1; fi
    [[ -z $(ss -H -ltn "( sport = :$PANEL_PORT )") ]] || die "端口 $PANEL_PORT 已被其他程序占用"
    if ! id tg-relay >/dev/null 2>&1; then useradd --system --user-group --home-dir "$DATA_DIR" --shell /usr/sbin/nologin tg-relay; fi
    if [[ -n $admin_action ]]; then
        printf '%s' "$ADMIN_PASSWORD" | "$WORK_DIR/tg-relay" "$admin_action" -admin-user "$ADMIN_USER" -data "$DATA_DIR"
        printf '%s' "$ADMIN_PASSWORD" | "$WORK_DIR/tg-relay" -verify-admin -admin-user "$ADMIN_USER" -data "$DATA_DIR" || die '新账号密码校验失败，未启动服务'
        unset ADMIN_PASSWORD
    fi
    install -d -m 0755 "$INSTALL_DIR"
    # Replace the original executable only after download, checksum, input and port checks have passed.
    install -m 0755 "$WORK_DIR/tg-relay" "$INSTALL_DIR/tg-relay"
    install -m 0644 "$WORK_DIR/LICENSE.mtg" "$WORK_DIR/THIRD_PARTY_NOTICES.md" "$INSTALL_DIR/"
    install -m 0644 "$WORK_DIR/tg-relay.service" "$UNIT"
    install -m 0755 "$WORK_DIR/install.sh" "$INSTALL_DIR/manage.sh"
    install -d -m 0755 "$(dirname "$MENU_COMMAND")"
    if [[ ! -L $MENU_COMMAND ]]; then ln -s "$INSTALL_DIR/manage.sh" "$MENU_COMMAND"; fi
    install -m 0644 "$WORK_DIR/tg-relay-renew.service" "$WORK_DIR/tg-relay-renew.timer" /etc/systemd/system/
    if [[ -n $TLS_CERT ]]; then activate_certificate; fi
    write_configuration
    printf '%s\n' "$VERSION" > "$INSTALL_DIR/version"
    chown -R tg-relay:tg-relay "$DATA_DIR"
    chown root:tg-relay "$CONFIG_DIR"
    if [[ -n $TLS_CERT ]]; then certificate_deploy; configure_renewal; fi
    systemctl daemon-reload
    systemctl enable tg-relay.service
    systemctl restart tg-relay.service
    RESTART_ON_ERROR=0
    if wait_panel; then
        printf '\n安装完成，服务已响应。版本：%s\n管理员用户名：%s\n以后输入 tg 打开管理菜单。\n' "$VERSION" "$ADMIN_USER"
        show_panel
        return
    fi
    journalctl -u tg-relay -n 30 --no-pager >&2 || true
    die '服务未能响应，请检查上述日志；数据库已保留'
}
uninstall() {
    local answer
    ask answer '停止并删除程序与面板配置，保留数据；输入 UNINSTALL 确认' no
    [[ $answer == UNINSTALL ]] || die '已取消'
    systemctl disable --now tg-relay.service || true
    systemctl disable --now tg-relay-renew.timer || true
    rm -f -- "$UNIT" "$INSTALL_DIR/tg-relay" "$INSTALL_DIR/version" "$INSTALL_DIR/LICENSE.mtg" "$INSTALL_DIR/THIRD_PARTY_NOTICES.md" "$CONFIG_DIR/panel.conf"
    rm -f -- "$INSTALL_DIR/manage.sh" "$MENU_COMMAND" /etc/systemd/system/tg-relay-renew.service /etc/systemd/system/tg-relay-renew.timer
    rmdir -- "$INSTALL_DIR" "$CONFIG_DIR" 2>/dev/null || true
    systemctl daemon-reload
    printf '程序已卸载，数据及系统用户保留：%s\n' "$DATA_DIR"
}
main() {
    export LC_ALL=C
    local operation=menu
    while (($#)); do
        case "$1" in
            --version) [[ $# -ge 2 ]] || die '--version 缺少版本'; VERSION=$2; valid_version "$VERSION" || die '版本格式为 vX.Y.Z'; shift 2;;
            --renew-certificate) operation=renew; shift;;
            --certificate-deploy) operation=deploy; shift;;
            --help|-h) printf '用法：sudo bash install.sh [--version vX.Y.Z] 或 sudo tg\n支持安装/更新、账号密码重置、端口、域名、HTTPS 证书及续期、服务管理、保留数据卸载。\n'; return;;
            *) die "未知参数：$1";;
        esac
    done
    [[ $(uname -s) == Linux ]] || die '此安装脚本仅用于 Linux'
    [[ $EUID == 0 ]] || die '请使用 sudo bash install.sh 或切换 root'
    umask 077
    safe_paths
    if [[ $operation == deploy ]]; then read_configuration; certificate_deploy; return; fi
    [[ -d /run/systemd/system ]] || die '需要使用 systemd 的 Linux 系统'
    local command choice
    for command in curl tar sha256sum awk ss flock useradd install systemctl; do command -v "$command" >/dev/null || die "缺少命令 $command，请先安装 curl ca-certificates tar coreutils iproute2 util-linux passwd"; done
    exec 9>/run/tg-relay-install.lock
    flock -n 9 || die '另一个安装器正在运行'
    trap cleanup EXIT
    if [[ $operation == renew ]]; then renew_certificate; return; fi
    exec 3<>/dev/tty || die '需要交互终端，请在 SSH 终端运行'
    trap 'exit 130' INT
    trap 'exit 143' TERM
    local action_status installed_version
    while true; do
        installed_version=未安装
        if [[ -f $INSTALL_DIR/version ]]; then installed_version=$(cat "$INSTALL_DIR/version"); fi
        printf '\nTG Relay 管理菜单 [%s]\n1) 安装 / 更新\n2) 查看面板地址和管理员用户名\n3) 修改面板端口 / IP / 域名 / 访问方式\n4) 重置管理员账号和密码\n5) 启动服务\n6) 停止服务（断开已有 TG 连接）\n7) 重启服务（断开已有 TG 连接）\n8) 服务状态和日志\n9) HTTPS 证书申请 / 导入 / 续期\n10) 设置开机自启\n11) 卸载程序（保留数据和证书）\n0) 退出\n' "$installed_version" >&3
        ask choice '选择操作' 0
        [[ $choice != 0 ]] || return
        # Keep each operation strict, but return to the menu after a failed operation.
        set +e
        (
            set -Eeuo pipefail
            trap cleanup EXIT
            case "$choice" in
                1) install_release;;
                2) show_panel;;
                3) change_panel;;
                4) reset_admin_credentials;;
                5) require_installed; systemctl start tg-relay.service;;
                6) require_installed; systemctl stop tg-relay.service;;
                7) require_installed; systemctl restart tg-relay.service;;
                8) systemctl status tg-relay.service --no-pager || true; journalctl -u tg-relay -n 50 --no-pager;;
                9) certificate_menu;;
                10) ask choice '1 启用开机自启，2 关闭开机自启' 1; case "$choice" in 1) systemctl enable tg-relay.service;; 2) systemctl disable tg-relay.service;; *) die '请选择 1 或 2';; esac;;
                11) uninstall;;
                *) die '无效操作';;
            esac
        )
        action_status=$?
        set -e
        if ((action_status != 0)); then printf '操作未完成（退出码 %s），可修改后重试。\n' "$action_status" >&3; fi
        printf '按回车返回菜单…' >&3
        IFS= read -r choice <&3 || return
    done
}
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
