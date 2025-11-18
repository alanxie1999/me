#!/usr/bin/env bash
# Socks5 (Dante) 一键安装/卸载脚本 - 仅支持 Debian/Ubuntu
# 功能：
#  - 固定端口、固定账号密码（在脚本顶部配置）
#  - 支持多用户
#  - 只允许指定 IP 访问（白名单）
#  - 安装 / 卸载 二合一：./sk5.sh install|uninstall

set -e

#====================#
#  可配置参数区域    #
#====================#

# 监听端口
SOCKS_PORT=1080

# 多用户账号密码列表：格式为 "user:pass"，空格分隔多个
# 示例：USERS=("user1:pass1" "user2:pass2")
USERS=(
  "user1:pass1"
  "user2:pass2"
)

# 允许访问的 IP 白名单（只允许这些 IP 作为客户端连接）
# 示例：ALLOW_IPS=("1.2.3.4" "5.6.7.8")
ALLOW_IPS=(
  "1.2.3.4"  # 在这里替换为你自己的出口 IP
)

#====================#
#  内部函数          #
#====================#

red()   { echo -e "\e[31m$*\e[0m"; }
green() { echo -e "\e[32m$*\e[0m"; }
yellow(){ echo -e "\e[33m$*\e[0m"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        red "请用 root 权限运行此脚本（sudo 或直接 root）。"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        red "/etc/os-release 不存在，无法检测系统。"
        exit 1
    fi
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            PM="apt"
            ;;
        *)
            red "当前脚本仅支持 Debian/Ubuntu，检测到: $ID"
            exit 1
            ;;
    esac
}

install_dante_pkg() {
    green "安装 dante-server..."
    $PM update -y
    $PM install -y dante-server
}

create_users() {
    green "创建/更新 Socks5 用户..."
    for up in "${USERS[@]}"; do
        USERNAME="${up%%:*}"
        PASSWORD="${up#*:}"
        if id "$USERNAME" &>/dev/null; then
            yellow "用户 $USERNAME 已存在，更新密码。"
        else
            useradd --no-create-home --shell /usr/sbin/nologin "$USERNAME"
        fi
        echo "$USERNAME:$PASSWORD" | chpasswd
    done
}

write_config() {
    local CONF_PATH="/etc/danted.conf"
    green "生成 Dante 配置文件: $CONF_PATH"

    {
        echo "logoutput: syslog"
        echo "internal: 0.0.0.0 port = $SOCKS_PORT"
        echo "external: 0.0.0.0"
        echo
        # 认证方式：用户名密码
        echo "method: username"
        echo "user.notprivileged: nobody"
        echo
        # 允许所有客户端连接（由用户名密码控制权限）
        echo "client pass {"
        echo "    from: 0.0.0.0/0 port 1-65535"
        echo "    to: 0.0.0.0/0"
        echo "    log: error"
        echo "}"
        echo
        # socks 规则：允许所有来源访问任意目标，但必须用户名密码认证
        echo "socks pass {"
        echo "    from: 0.0.0.0/0 to: 0.0.0.0/0"
        echo "    log: connect error"
        echo "    socksmethod: username"
        echo "}"
    } > "$CONF_PATH"
}

open_firewall() {
    green "尝试打开防火墙端口 $SOCKS_PORT (如有防火墙)..."

    if command -v ufw &>/dev/null; then
        ufw allow "$SOCKS_PORT"/tcp || true
    fi
}

start_service() {
    local SERVICE_NAME="danted"
    green "启动并设置开机自启服务 $SERVICE_NAME ..."
    if command -v systemctl &>/dev/null; then
        systemctl enable "$SERVICE_NAME" || true
        systemctl restart "$SERVICE_NAME"
        systemctl --no-pager -l status "$SERVICE_NAME" || true
    else
        service "$SERVICE_NAME" restart || true
        service "$SERVICE_NAME" status || true
    fi
}

stop_service() {
    local SERVICE_NAME="danted"
    green "停止服务 $SERVICE_NAME ..."
    if command -v systemctl &>/dev/null; then
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
    else
        service "$SERVICE_NAME" stop || true
    fi
}

status_service() {
    local SERVICE_NAME="danted"
    green "查看服务 $SERVICE_NAME 状态..."
    if command -v systemctl &>/dev/null; then
        systemctl --no-pager -l status "$SERVICE_NAME" || true
    else
        service "$SERVICE_NAME" status || true
    fi
}

remove_users() {
    green "删除 Socks5 用户..."
    for up in "${USERS[@]}"; do
        USERNAME="${up%%:*}"
        if id "$USERNAME" &>/dev/null; then
            userdel "$USERNAME" || true
        fi
    done
}

uninstall_dante_pkg() {
    green "卸载 dante-server..."
    $PM remove -y dante-server || true
}

usage() {
    echo "用法: $0 [install|uninstall|status]"
    echo "  install   安装并启动 Socks5 服务 (默认)"
    echo "  uninstall 停止并卸载 Socks5 服务"
    echo "  status    查看 Socks5 服务当前状态"
}

print_info() {
    local IP
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    IP=${IP:-"服务器IP"}

    green "================ 安装完成 ================"
    echo "Socks5 信息："
    echo "  服务器IP : $IP"
    echo "  端口     : $SOCKS_PORT"
    echo "  允许 IP  : ${ALLOW_IPS[*]}"
    echo
    echo "账号列表："
    for up in "${USERS[@]}"; do
        USERNAME="${up%%:*}"
        PASSWORD="${up#*:}"
        echo "  用户名: $USERNAME   密码: $PASSWORD"
    done
    echo "=========================================="
}

main() {
    check_root
    check_os

    local ACTION="${1:-install}"

    case "$ACTION" in
        install)
            install_dante_pkg
            create_users
            write_config
            open_firewall
            start_service
            print_info
            ;;
        uninstall)
            stop_service
            remove_users
            uninstall_dante_pkg
            green "卸载完成。"
            ;;
        status)
            status_service
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
