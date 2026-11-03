#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY=wstimin/tg-relay
INSTALL_DIR=/opt/tg-relay
DATA_DIR=/var/lib/tg-relay
CONFIG_DIR=/etc/tg-relay
UNIT=/etc/systemd/system/tg-relay.service
WORK_DIR=
RESTART_ON_ERROR=0
VERSION=

die() { printf '错误：%s\n' "$*" >&2; exit 1; }
valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
valid_host() {
    [[ ${#1} -le 253 && $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && $1 != *..* ]]
}
valid_username() { [[ $1 =~ ^[a-zA-Z0-9_.-]{1,64}$ ]]; }
valid_version() { [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
architecture() {
    case "$1" in x86_64|amd64) printf amd64;; aarch64|arm64) printf arm64;; *) return 1;; esac
}
download() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2 "$@"; }
ask() {
    local answer
    printf '%s [%s]：' "$2" "$3" >&3
    IFS= read -r answer <&3 || die '输入中断'
    printf -v "$1" '%s' "${answer:-$3}"
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
    for path in "$INSTALL_DIR" "$DATA_DIR" "$CONFIG_DIR" "$UNIT"; do
        [[ ! -L $path ]] || die "拒绝操作符号链接：$path"
    done
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
    if [[ -f $CONFIG_DIR/panel.conf ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                TG_RELAY_LISTEN) LISTEN=$value;;
                TG_RELAY_ADMIN_HOST) ADMIN_HOST=$value;;
                TG_RELAY_SECURE_COOKIE) SECURE_COOKIE=$value;;
            esac
        done < "$CONFIG_DIR/panel.conf"
    fi
}
configure_panel() {
    local default_port=${LISTEN##*:} mode=1 bind_ip
    valid_port "$default_port" || default_port=8765
    ask PANEL_PORT '面板访问端口（与 TG 入站端口独立）' "$default_port"
    valid_port "$PANEL_PORT" || die '端口必须是 1–65535'
    PANEL_PORT=$((10#$PANEL_PORT))
    printf '\n1) 本机访问 / SSH 隧道（推荐）\n2) 公网 HTTP（密码和会话未经 HTTPS 保护）\n3) 已有 HTTPS 反向代理\n' >&3
    case "$LISTEN:$SECURE_COOKIE" in 0.0.0.0:*:false) mode=2;; *:true) mode=3;; esac
    ask mode '面板访问方式' "$mode"
    SECURE_COOKIE=false
    case "$mode" in
        1) bind_ip=127.0.0.1; ADMIN_HOST=localhost;;
        2) bind_ip=0.0.0.0; ask ADMIN_HOST '访问面板使用的服务器 IPv4 / 域名（不带协议和端口）' "$ADMIN_HOST"; [[ $ADMIN_HOST != localhost && $ADMIN_HOST != 127.* && $ADMIN_HOST != 0.0.0.0 ]] || die '公网方式请填写真实服务器地址';;
        3) bind_ip=127.0.0.1; ask ADMIN_HOST '已有 HTTPS 面板域名（不带协议和端口）' "$ADMIN_HOST"; [[ $ADMIN_HOST != localhost ]] || die '请填写 HTTPS 域名'; SECURE_COOKIE=true;;
        *) die '访问方式必须为 1、2 或 3';;
    esac
    valid_host "$ADMIN_HOST" || die '主机名无效；当前安装器支持 IPv4 或 ASCII 域名'
    LISTEN="$bind_ip:$PANEL_PORT"
}
read_admin() {
    ask ADMIN_USER '管理员用户名（字母、数字、下划线、点或连字符）' admin
    valid_username "$ADMIN_USER" || die '用户名必须为 1–64 个允许的字符'
    while true; do
        printf '管理员密码（12–256 字节，隐藏输入）：' >&3
        IFS= read -r -s ADMIN_PASSWORD <&3 || die '密码输入中断'
        printf '\n再次输入密码：' >&3
        IFS= read -r -s PASSWORD_CONFIRM <&3 || die '密码输入中断'
        printf '\n' >&3
        if [[ ${#ADMIN_PASSWORD} -ge 12 && ${#ADMIN_PASSWORD} -le 256 && $ADMIN_PASSWORD == "$PASSWORD_CONFIRM" ]]; then break; fi
        printf '长度不符合要求或两次密码不一致，请重试。\n' >&3
    done
    unset PASSWORD_CONFIRM
}
install_release() {
    local arch asset release_url status active=0
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
    tar --extract --gzip --file "$WORK_DIR/$asset" --directory "$WORK_DIR" --no-same-owner tg-relay tg-relay.service LICENSE.mtg THIRD_PARTY_NOTICES.md
    [[ -f $WORK_DIR/tg-relay && ! -L $WORK_DIR/tg-relay && -f $WORK_DIR/tg-relay.service && ! -L $WORK_DIR/tg-relay.service ]] || die '发布包内容无效'
    chmod 0755 "$WORK_DIR/tg-relay"
    read_configuration
    configure_panel
    install -d -m 0700 "$DATA_DIR" "$CONFIG_DIR"
    status=$("$WORK_DIR/tg-relay" -admin-status -data "$DATA_DIR")
    [[ $status == initialized || $status == uninitialized ]] || die '无法读取管理员状态'
    if [[ $status == uninitialized ]]; then read_admin; else printf '保留已有管理员、密钥和流量数据，不重设密码。\n'; fi
    systemctl is-active --quiet tg-relay.service && active=1
    if ((active)); then systemctl stop tg-relay.service; RESTART_ON_ERROR=1; fi
    [[ -z $(ss -H -ltn "( sport = :$PANEL_PORT )") ]] || die "端口 $PANEL_PORT 已被其他程序占用"
    if ! id tg-relay >/dev/null 2>&1; then useradd --system --user-group --home-dir "$DATA_DIR" --shell /usr/sbin/nologin tg-relay; fi
    if [[ $status == uninitialized ]]; then
        printf '%s' "$ADMIN_PASSWORD" | "$WORK_DIR/tg-relay" -init-admin -admin-user "$ADMIN_USER" -data "$DATA_DIR"
        unset ADMIN_PASSWORD
    fi
    install -d -m 0755 "$INSTALL_DIR"
    # Replace the original executable only after download, checksum, input and port checks have passed.
    install -m 0755 "$WORK_DIR/tg-relay" "$INSTALL_DIR/tg-relay"
    install -m 0644 "$WORK_DIR/LICENSE.mtg" "$WORK_DIR/THIRD_PARTY_NOTICES.md" "$INSTALL_DIR/"
    install -m 0644 "$WORK_DIR/tg-relay.service" "$UNIT"
    printf 'TG_RELAY_LISTEN=%s\nTG_RELAY_ADMIN_HOST=%s\nTG_RELAY_SECURE_COOKIE=%s\n' "$LISTEN" "$ADMIN_HOST" "$SECURE_COOKIE" > "$CONFIG_DIR/panel.conf"
    printf '%s\n' "$VERSION" > "$INSTALL_DIR/version"
    chown -R tg-relay:tg-relay "$DATA_DIR"
    systemctl daemon-reload
    systemctl enable tg-relay.service
    systemctl restart tg-relay.service
    RESTART_ON_ERROR=0
    for _ in {1..20}; do
        if systemctl is-active --quiet tg-relay.service && curl --fail --silent --noproxy '*' --connect-timeout 1 --max-time 2 "http://127.0.0.1:$PANEL_PORT/api/auth" >/dev/null; then
            printf '\n安装完成，服务已响应。版本：%s\n' "$VERSION"
            case "$LISTEN:$SECURE_COOKIE" in
                *:true) printf '访问：https://%s （请确认已有反向代理转发到 127.0.0.1:%s 并保留 Host）\n' "$ADMIN_HOST" "$PANEL_PORT";;
                127.0.0.1:*) printf 'SSH 隧道：ssh -L %s:127.0.0.1:%s 你的SSH用户@服务器\n浏览器：http://127.0.0.1:%s\n' "$PANEL_PORT" "$PANEL_PORT" "$PANEL_PORT";;
                *) printf '访问：http://%s:%s\n请放行云安全组和防火墙的 TCP %s；建议配置 HTTPS。\n' "$ADMIN_HOST" "$PANEL_PORT" "$PANEL_PORT";;
            esac
            printf '管理命令：systemctl status|restart|stop tg-relay\n日志：journalctl -u tg-relay -n 50 --no-pager\n'
            return
        fi
        sleep 1
    done
    journalctl -u tg-relay -n 30 --no-pager >&2 || true
    die '服务未能响应，请检查上述日志；数据库已保留'
}
uninstall() {
    local answer
    ask answer '停止并删除程序与面板配置，保留数据；输入 UNINSTALL 确认' no
    [[ $answer == UNINSTALL ]] || die '已取消'
    systemctl disable --now tg-relay.service || true
    rm -f -- "$UNIT" "$INSTALL_DIR/tg-relay" "$INSTALL_DIR/version" "$INSTALL_DIR/LICENSE.mtg" "$INSTALL_DIR/THIRD_PARTY_NOTICES.md" "$CONFIG_DIR/panel.conf"
    rmdir -- "$INSTALL_DIR" "$CONFIG_DIR" 2>/dev/null || true
    systemctl daemon-reload
    printf '程序已卸载，数据及系统用户保留：%s\n' "$DATA_DIR"
}
main() {
    export LC_ALL=C
    while (($#)); do
        case "$1" in
            --version) [[ $# -ge 2 ]] || die '--version 缺少版本'; VERSION=$2; valid_version "$VERSION" || die '版本格式为 vX.Y.Z'; shift 2;;
            --help|-h) printf '用法：sudo bash install.sh [--version vX.Y.Z]\n支持安装/更新、修改端口和访问方式、状态日志、保留数据卸载。\n'; return;;
            *) die "未知参数：$1";;
        esac
    done
    [[ $(uname -s) == Linux ]] || die '此安装脚本仅用于 Linux'
    [[ $EUID == 0 ]] || die '请使用 sudo bash install.sh 或切换 root'
    [[ -d /run/systemd/system ]] || die '需要使用 systemd 的 Linux 系统'
    local command choice
    for command in curl tar sha256sum awk ss flock useradd install systemctl; do command -v "$command" >/dev/null || die "缺少命令 $command，请先安装 curl ca-certificates tar coreutils iproute2 util-linux passwd"; done
    exec 9>/run/tg-relay-install.lock
    flock -n 9 || die '另一个安装器正在运行'
    exec 3<>/dev/tty || die '需要交互终端，请在 SSH 终端运行'
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    umask 077
    safe_paths
    printf '\nTG Relay 安装管理\n1) 安装 / 更新（可选端口与访问方式）\n2) 服务状态及日志\n3) 卸载程序（保留数据）\n0) 退出\n' >&3
    ask choice '选择操作' 1
    case "$choice" in
        1) install_release;;
        2) systemctl status tg-relay.service --no-pager || true; journalctl -u tg-relay -n 30 --no-pager;;
        3) uninstall;;
        0) return;;
        *) die '无效操作';;
    esac
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
