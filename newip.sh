#!/bin/bash

# =========================================================
# 综合隧道管理脚本：IPIP / WireGuard / Gost 一体化管理
# 整合版：包含完整的 Gost 配置功能
# =========================================================

# --- 全局颜色变量 ---
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Green_background_prefix="\033[42;37m"
Font_color_suffix="\033[0m"
red='\033[0;31m'
green='\033[0;32m'
white='\033[37m'
blue='\033[36m'
yellow='\033[0;33m'
plain='\033[0m'

Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"

# --- 版本与路径 ---
shell_version="1.8.0"
ct_new_ver="2.11.2"
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"
keeper_script_path="/usr/local/bin/ipip-ddns-keeper.sh"
ddns_conf_dir="/etc/ipip-ddns"
backup_base_dir="/root/tunnel-backups"

DATE=$(date +%Y%m%d)

# =========================================================
# 权限检查
# =========================================================
check_root() {
  [[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，请使用 ${green}sudo su${plain} 获取权限。" && exit 1
}

# =========================================================
# 公共工具函数
# =========================================================

# 获取主网络接口
get_main_interface() {
  local iface=""
  # IPv4 检测（优先）
  iface=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{print $5;exit}')
  [[ -z "$iface" ]] && iface=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{print $5;exit}')
  # IPv6 检测（备用）
  [[ -z "$iface" ]] && iface=$(ip route get 2001:4860:4860::8888 2>/dev/null | awk '/dev/{print $5;exit}')
  # 系统目录检测（最后备用）
  [[ -z "$iface" ]] && iface=$(ls /sys/class/net | grep -v '^lo$' | head -n1)
  echo "$iface"
}

# 备份配置文件
backup_config() {
  local config_type="$1"  # wireguard, ipip, gost
  local config_name="$2"  # 配置名称（如接口名、文件名）
  local config_path="$3"  # 配置文件路径
  
  # 创建备份目录：/root/tunnel-backups/YYYYMMDD-HHMMSS/
  local backup_dir="${backup_base_dir}/$(date +%Y%m%d-%H%M%S)"
  local type_dir="${backup_dir}/${config_type}"
  
  mkdir -p "$type_dir" || {
    echo -e "${yellow}警告: 无法创建备份目录 ${backup_dir}${plain}"
    return 1
  }
  
  # 备份配置文件
  if [[ -f "$config_path" ]]; then
    local backup_file="${type_dir}/${config_name}"
    cp "$config_path" "$backup_file" 2>/dev/null || {
      echo -e "${yellow}警告: 无法备份 ${config_path}${plain}"
      return 1
    }
    echo -e "${green}✓ 配置已备份到: ${backup_file}${plain}"
    return 0
  elif [[ -d "$config_path" ]]; then
    # 如果是目录，备份整个目录
    local backup_name="${config_name}.tar.gz"
    tar -czf "${type_dir}/${backup_name}" -C "$(dirname "$config_path")" "$(basename "$config_path")" 2>/dev/null || {
      echo -e "${yellow}警告: 无法备份目录 ${config_path}${plain}"
      return 1
    }
    echo -e "${green}✓ 配置目录已备份到: ${type_dir}/${backup_name}${plain}"
    return 0
  else
    echo -e "${yellow}提示: 配置文件 ${config_path} 不存在，跳过备份${plain}"
    return 0
  fi
}

# 备份 WireGuard 配置
backup_wireguard_config() {
  local wg_interface="$1"
  local config_file="/etc/wireguard/${wg_interface}.conf"
  
  # 备份配置文件
  backup_config "wireguard" "${wg_interface}.conf" "$config_file"
  
  # 备份密钥文件（如果存在）
  local privatekey_file="/etc/wireguard/privatekey"
  local publickey_file="/etc/wireguard/${wg_interface}_publickey"
  [[ -f "$privatekey_file" ]] && backup_config "wireguard" "privatekey" "$privatekey_file"
  [[ -f "$publickey_file" ]] && backup_config "wireguard" "${wg_interface}_publickey" "$publickey_file"
}

# 备份 IPIP 配置
backup_ipip_config() {
  local tun_name="$1"
  local backup_dir="${backup_base_dir}/$(date +%Y%m%d-%H%M%S)/ipip"
  mkdir -p "$backup_dir" || return 1
  
  # 备份 systemd timer 和 service
  local timer_file="/etc/systemd/system/ipip-${tun_name}-keeper.timer"
  local service_file="/etc/systemd/system/ipip-${tun_name}-keeper.service"
  local ddns_conf="${ddns_conf_dir}/${tun_name}.conf"
  
  [[ -f "$timer_file" ]] && cp "$timer_file" "${backup_dir}/" 2>/dev/null
  [[ -f "$service_file" ]] && cp "$service_file" "${backup_dir}/" 2>/dev/null
  [[ -f "$ddns_conf" ]] && cp "$ddns_conf" "${backup_dir}/" 2>/dev/null
  
  # 备份 keeper 脚本
  [[ -f "$keeper_script_path" ]] && cp "$keeper_script_path" "${backup_dir}/" 2>/dev/null
  
  echo -e "${green}✓ IPIP 配置已备份到: ${backup_dir}${plain}"
}

# 备份 Gost 配置
backup_gost_config() {
  local backup_dir="${backup_base_dir}/$(date +%Y%m%d-%H%M%S)/gost"
  mkdir -p "$backup_dir" || return 1
  
  # 备份配置文件
  [[ -f "$gost_conf_path" ]] && cp "$gost_conf_path" "${backup_dir}/" 2>/dev/null
  [[ -f "$raw_conf_path" ]] && cp "$raw_conf_path" "${backup_dir}/" 2>/dev/null
  
  # 备份整个配置目录（如果存在）
  if [[ -d "/etc/gost" ]]; then
    tar -czf "${backup_dir}/gost-config.tar.gz" -C /etc gost 2>/dev/null
  fi
  
  echo -e "${green}✓ Gost 配置已备份到: ${backup_dir}${plain}"
}

# 显示 ping 测试提醒
show_ping_reminder() {
  local remote_ip="$1"
  local tunnel_type="$2"  # ipip, ipipv6, wireguard
  
  echo ""
  echo -e "${yellow}═══════════════════════════════════════════════════════════${plain}"
  echo -e "${yellow}测试连通性提醒：${plain}"
  echo -e "${green}建议测试对端连通性，请执行以下命令：${plain}"
  
  if echo "$remote_ip" | grep -q ':' || [[ "$tunnel_type" == "ipipv6" ]]; then
    echo -e "${blue}  ping6 -c 4 ${remote_ip}${plain}"
  else
    echo -e "${blue}  ping -c 4 ${remote_ip}${plain}"
  fi
  
  echo -e "${yellow}如果无法 ping 通，请检查：${plain}"
  case "$tunnel_type" in
    ipip)
      echo -e "${yellow}  1. 对端 IPIP 隧道是否已正确配置${plain}"
      echo -e "${yellow}  2. 对端防火墙规则是否允许 ICMP 包${plain}"
      echo -e "${yellow}  3. 路由表是否正确：ip route show${plain}"
      ;;
    ipipv6)
      echo -e "${yellow}  1. 对端 IPIPv6 隧道是否已正确配置${plain}"
      echo -e "${yellow}  2. 对端防火墙规则是否允许 ICMPv6 包${plain}"
      echo -e "${yellow}  3. IPv6 路由表是否正确：ip -6 route show${plain}"
      ;;
    wireguard)
      echo -e "${yellow}  1. 对端 WireGuard 接口是否已正确配置和启动${plain}"
      echo -e "${yellow}  2. 对端防火墙规则是否允许 ICMP 包${plain}"
      echo -e "${yellow}  3. WireGuard 连接状态：wg show${plain}"
      echo -e "${yellow}  4. 路由表是否正确：ip route show${plain}"
      ;;
  esac
  echo -e "${yellow}═══════════════════════════════════════════════════════════${plain}"
}

# 交互兜底与可控清屏
if [ ! -t 0 ] || [ ! -t 1 ]; then exec </dev/tty >/dev/tty 2>/dev/tty || true; fi
: "${CLEAR_CMD:=clear}"; alias clear="${CLEAR_CMD}"

# =========================================================
# 系统检测
# =========================================================
check_sys() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian) release="debian" ;;
      centos|rhel|rocky|almalinux) release="centos" ;;
      *) release="unknown" ;;
    esac
  elif [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif grep -qi "debian" /etc/issue 2>/dev/null; then
    release="debian"
  else
    release="unknown"
  fi

  bit=$(uname -m)
  if [[ "$bit" != "x86_64" ]]; then
    echo -e "${yellow}检测到非 x86_64 架构，请手动输入 (如 arm64, armv7 等):${plain}"
    read -p "架构: " bit
  else
    bit="amd64"
  fi
  [[ "$bit" == "aarch64" ]] && bit="arm64"
}

# =========================================================
# DDNS 自愈守护（域名或静态 IP 均使用）
# =========================================================
install_ddns_keeper() {
  local tunname="$1" mode="$2" ddns="$3" local_ip="$4" vip_cidr="$5" remote_vip="$6"

  install -d -m 755 "$ddns_conf_dir"
  # 原子写入 env，避免半写导致配置丢失
  local tmp_env
  tmp_env="$(mktemp "${ddns_conf_dir}/${tunname}.env.XXXXXX")"
  cat >"$tmp_env" <<EOF
MODE=${mode}
DDNS_NAME=${ddns}
LOCAL_IP=${local_ip}
VIP_CIDR=${vip_cidr}
REMOTE_VIP=${remote_vip}
EOF
  chmod 600 "$tmp_env"
  mv -f "$tmp_env" "${ddns_conf_dir}/${tunname}.env"
  echo -e "${Info} 配置文件已保存并设置为仅 root 可读 (权限 600)"

  if [[ ! -x "$keeper_script_path" ]]; then
    cat >"$keeper_script_path" <<'KEEPER_EOF'
#!/usr/bin/env bash
set -euo pipefail

TUN_NAME="${1:-}"
if [[ -z "$TUN_NAME" ]]; then
  echo "Usage: $0 <tun_name>" >&2
  exit 2
fi

CONF_DIR="/etc/ipip-ddns"
CONF_FILE="${CONF_DIR}/${TUN_NAME}.env"
STATE_DIR="/run/ipip-ddns"
mkdir -p "$STATE_DIR"
STATE_FILE="${STATE_DIR}/${TUN_NAME}.state"
PERSIST_FILE="${CONF_DIR}/${TUN_NAME}.state"
LOCK_FILE="${STATE_DIR}/${TUN_NAME}.lock"

if [[ ! -f "$CONF_FILE" ]]; then
  echo "Config not found: $CONF_FILE" >&2
  exit 1
fi

source "$CONF_FILE"

: "${MODE:?v4|v6}"
: "${DDNS_NAME:?}"
: "${LOCAL_IP:?}"
: "${VIP_CIDR:?}"
: "${REMOTE_VIP:?}"

# 更新 env 中的 RESOLVED_IP 字段
update_env_resolved_ip() {
  local env_file="$CONF_FILE" tmp
  tmp="$(mktemp "${env_file}.XXXXXX")" || return 0
  if grep -q '^RESOLVED_IP=' "$env_file" 2>/dev/null; then
    sed 's/^RESOLVED_IP=.*/RESOLVED_IP='"$REMOTE_IP"'/' "$env_file" >"$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  else
    cat "$env_file" >"$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
    printf '\nRESOLVED_IP=%s\n' "$REMOTE_IP" >>"$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  fi
  mv -f "$tmp" "$env_file" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

resolve_ip() {
  if [[ "$MODE" == "v6" ]]; then
    getent hosts "$DDNS_NAME" | awk '{print $1}' | grep -E '^[0-9a-fA-F:]+$' | head -n1 || \
    dig +short AAAA "$DDNS_NAME" | head -n1 || \
    ping6 -c1 "$DDNS_NAME" 2>/dev/null | grep -Eo '([0-9a-fA-F:]+)' | head -n1 || true
  else
    getent hosts "$DDNS_NAME" | awk '{print $1}' | grep -E '^[0-9.]+$' | head -n1 || \
    dig +short A "$DDNS_NAME" | head -n1 || \
    ping -4 -c1 "$DDNS_NAME" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1 || true
  fi
}

with_lock() { exec 9>"$LOCK_FILE"; flock -n 9; }

# 解析（带重试）
resolve_ip_try() {
  local name="$1" mode="$2" ip="" attempt=0
  while (( attempt < 3 )); do
    if [[ "$mode" == "v6" ]]; then
      ip=$(getent hosts "$name" | awk '{print $1}' | grep -E '^[0-9a-fA-F:]+$' | head -n1 || true)
      [[ -z "$ip" ]] && ip=$(dig +short AAAA "$name" | head -n1 || true)
    else
      ip=$(getent hosts "$name" | awk '{print $1}' | grep -E '^[0-9.]+$' | head -n1 || true)
      [[ -z "$ip" ]] && ip=$(dig +short A "$name" | head -n1 || true)
    fi
    [[ -n "$ip" ]] && { echo "$ip"; return 0; }
    sleep 1; ((attempt++))
  done
  echo ""
}

# 幂等重建接口/地址/路由
ensure_ipip_stack() {
  local name="$1" mode="$2" local_ip="$3" remote_ip="$4" vip_cidr="$5" remote_vip="$6"
  
  # 关闭接口
  ip link set "$name" down 2>/dev/null || true
  
  if [[ "$mode" == "v6" ]]; then
    # 删除旧隧道
    ip -6 tunnel del "$name" 2>/dev/null || true
    
    # 创建新隧道
    if ! ip link add name "$name" type ip6tnl local "$local_ip" remote "$remote_ip" mode any 2>/dev/null; then
      echo "$(date) $name: 创建 IPv6 隧道失败" >&2
      return 1
    fi
    
    # 清理旧地址并添加新地址
    ip -6 addr flush dev "$name" 2>/dev/null || true
    if ! ip -6 addr add "$vip_cidr" dev "$name" 2>/dev/null; then
      echo "$(date) $name: 添加 IPv6 地址失败" >&2
      return 1
    fi
  else
    # 删除旧隧道
    ip tunnel del "$name" 2>/dev/null || true
    
    # 创建新隧道
    if ! ip tunnel add "$name" mode ipip remote "$remote_ip" local "$local_ip" ttl 64 2>/dev/null; then
      echo "$(date) $name: 创建 IPIP 隧道失败" >&2
      return 1
    fi
    
    # 清理旧地址并添加新地址
    ip addr flush dev "$name" 2>/dev/null || true
    if ! ip addr add "$vip_cidr" dev "$name" 2>/dev/null; then
      echo "$(date) $name: 添加 IP 地址失败" >&2
      return 1
    fi
  fi
  
  # 启动接口
  if ! ip link set "$name" up 2>/dev/null; then
    echo "$(date) $name: 启动接口失败" >&2
    return 1
  fi
  
  # 添加路由
  if [[ -n "$remote_vip" ]]; then
    if [[ "$remote_vip" == *:* ]]; then
      if ! ip -6 route replace "${remote_vip}/128" dev "$name" scope link src "${vip_cidr%/*}" 2>/dev/null; then
        echo "$(date) $name: 添加 IPv6 路由失败" >&2
      fi
    else
      if ! ip route replace "${remote_vip}/32" dev "$name" scope link src "${vip_cidr%/*}" 2>/dev/null; then
        echo "$(date) $name: 添加路由失败" >&2
      fi
    fi
  fi
  
  return 0
}

REMOTE_IP=""
if [[ "$DDNS_NAME" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$DDNS_NAME" =~ ^[0-9a-fA-F:]+$ ]]; then
  REMOTE_IP="$DDNS_NAME"
else
  REMOTE_IP="$(resolve_ip_try "$DDNS_NAME" "$MODE")"
fi

if [[ -z "$REMOTE_IP" ]]; then
  PREV_REMOTE_LOCAL="$(cat "$STATE_FILE" 2>/dev/null || true)"
  [[ -z "$PREV_REMOTE_LOCAL" ]] && PREV_REMOTE_LOCAL="$(cat "$PERSIST_FILE" 2>/dev/null || true)"
  if [[ -n "$PREV_REMOTE_LOCAL" ]]; then
    echo "$(date) $TUN_NAME: DNS 解析失败，使用历史远端 $PREV_REMOTE_LOCAL 进行恢复" >&2
    with_lock || exit 0
    ensure_ipip_stack "$TUN_NAME" "$MODE" "$LOCAL_IP" "$PREV_REMOTE_LOCAL" "$VIP_CIDR" "$REMOTE_VIP"
    echo "$PREV_REMOTE_LOCAL" >"$STATE_FILE" 2>/dev/null || true
    exit 0
  else
    echo "$(date) $TUN_NAME: resolve failed and no previous IP" >&2
    exit 0
  fi
fi

with_lock || exit 0

PREV_REMOTE="$(cat "$STATE_FILE" 2>/dev/null || true)"
if [[ "$REMOTE_IP" == "$PREV_REMOTE" ]]; then
  ensure_ipip_stack "$TUN_NAME" "$MODE" "$LOCAL_IP" "$REMOTE_IP" "$VIP_CIDR" "$REMOTE_VIP"
  exit 0
fi

HAS_ROUTE="0"
if [[ "$MODE" == "v6" ]]; then
  if ip -6 route show | grep -qE "^${REMOTE_VIP}/128 dev ${TUN_NAME}"; then
    HAS_ROUTE="1"
  fi
else
  if ip route show | grep -qE "^${REMOTE_VIP}/32 dev ${TUN_NAME}"; then
    HAS_ROUTE="1"
  fi
fi

rollback() {
  if [[ -n "$PREV_REMOTE" ]]; then
    echo "$(date) $TUN_NAME: 配置失败，回滚到之前的远端 IP: $PREV_REMOTE" >&2
    if [[ "$MODE" == "v6" ]]; then
      ip link set "$TUN_NAME" down 2>/dev/null || true
      ip -6 tunnel del "$TUN_NAME" 2>/dev/null || true
      if ip link add name "$TUN_NAME" type ip6tnl local "$LOCAL_IP" remote "$PREV_REMOTE" mode any 2>/dev/null; then
        ip -6 addr flush dev "$TUN_NAME" 2>/dev/null || true
        ip -6 addr add "$VIP_CIDR" dev "$TUN_NAME" 2>/dev/null || true
        ip link set "$TUN_NAME" up 2>/dev/null || true
      else
        echo "$(date) $TUN_NAME: 回滚失败，无法创建 IPv6 隧道" >&2
      fi
    else
      ip link set "$TUN_NAME" down 2>/dev/null || true
      ip tunnel del "$TUN_NAME" 2>/dev/null || true
      if ip tunnel add "$TUN_NAME" mode ipip remote "$PREV_REMOTE" local "$LOCAL_IP" ttl 64 2>/dev/null; then
        ip addr flush dev "$TUN_NAME" 2>/dev/null || true
        ip addr add "$VIP_CIDR" dev "$TUN_NAME" 2>/dev/null || true
        ip link set "$TUN_NAME" up 2>/dev/null || true
      else
        echo "$(date) $TUN_NAME: 回滚失败，无法创建 IPIP 隧道" >&2
      fi
    fi
    if [[ "$HAS_ROUTE" == "1" ]]; then
      if [[ "$MODE" == "v6" ]]; then
        ip -6 route replace "${REMOTE_VIP}/128" dev "$TUN_NAME" scope link src "${VIP_CIDR%/*}" 2>/dev/null || true
      else
        ip route replace "${REMOTE_VIP}/32" dev "$TUN_NAME" scope link src "${VIP_CIDR%/*}" 2>/dev/null || true
      fi
    fi
  fi
}
trap rollback ERR

# IP 变更，重建
if ! ensure_ipip_stack "$TUN_NAME" "$MODE" "$LOCAL_IP" "$REMOTE_IP" "$VIP_CIDR" "$REMOTE_VIP"; then
  echo "$(date) $TUN_NAME: 配置失败" >&2
  exit 1
fi

# 新 IP 健康检查：如果新 IP 不通，则回滚到旧 IP
if [[ -n "$PREV_REMOTE" && -n "$REMOTE_VIP" ]]; then
  if [[ "$MODE" == "v6" ]]; then
    if ! ping6 -c1 -w2 "$REMOTE_VIP" >/dev/null 2>&1; then
      echo "$(date) $TUN_NAME: 新远端 IP $REMOTE_IP 不可达，回滚到 $PREV_REMOTE" >&2
      rollback
      exit 1
    fi
  else
    if ! ping -4 -c1 -w2 "$REMOTE_VIP" >/dev/null 2>&1; then
      echo "$(date) $TUN_NAME: 新远端 IP $REMOTE_IP 不可达，回滚到 $PREV_REMOTE" >&2
      rollback
      exit 1
    fi
  fi
fi

# 记录解析到的当前远端 IP
update_env_resolved_ip

# 重启相关的 WireGuard 接口
for conf in /etc/wireguard/*.conf; do
  [[ -f "$conf" ]] || continue
  IFACE="$(basename "$conf" .conf)"
  systemctl is-enabled "wg-quick@${IFACE}" >/dev/null 2>&1 || continue
  wg-quick down "$IFACE" >/dev/null 2>&1 || true
  wg-quick up "$IFACE" >/dev/null 2>&1 || true
done

# 保存状态
if ! echo "$REMOTE_IP" >"$STATE_FILE" 2>/dev/null; then
  echo "$(date) $TUN_NAME: 警告 - 无法保存运行时状态文件" >&2
fi
if ! echo "$REMOTE_IP" >"$PERSIST_FILE" 2>/dev/null; then
  echo "$(date) $TUN_NAME: 警告 - 无法保存持久化状态文件" >&2
fi

echo "$(date) $TUN_NAME: 配置成功，远端 IP: $REMOTE_IP" >&2
exit 0
KEEPER_EOF
    chmod 755 "$keeper_script_path"
  fi

  if [[ ! -f /etc/systemd/system/ipip-ddns@.service ]]; then
    cat >/etc/systemd/system/ipip-ddns@.service <<'SERVICE_EOF'
[Unit]
Description=IPIP DDNS keeper (%i)
After=network-online.target nss-lookup.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ipip-ddns-keeper.sh %i
Nice=5
IOSchedulingClass=best-effort
Restart=on-failure
RestartSec=5s
SERVICE_EOF
  fi

  if [[ ! -f /etc/systemd/system/ipip-ddns@.timer ]]; then
    cat >/etc/systemd/system/ipip-ddns@.timer <<'TIMER_EOF'
[Unit]
Description=IPIP DDNS keeper timer (%i)

[Timer]
OnBootSec=60s
OnUnitActiveSec=2min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF
  fi

  systemctl daemon-reload
  systemctl enable --now "ipip-ddns@${tunname}.timer"
  echo -e "${green}已启用 IPIP 自愈 (systemd timer)，每2分钟检查并自修复：${tunname}${plain}"
}

# =========================================================
# IPIP 管理函数
# =========================================================
view_ipip_interfaces() {
  clear
  echo -e "${blue}--- 已部署的 IPIP 接口 ---${plain}"
  local ipip_v4_links=$(ip -o link show type ipip | awk '{print $2}' | sed 's/://g;s/@NONE//g')
  local ipip_v6_links=$(ip -o link show type ip6tnl | awk '{print $2}' | sed 's/://g;s/@NONE//g')
  if [[ -z "$ipip_v4_links" && -z "$ipip_v6_links" ]]; then
    echo -e "${yellow}未检测到任何正在运行的 IPIP 隧道接口。${plain}"
    return
  fi

  if [[ -n "$ipip_v4_links" ]]; then
    echo -e "${green}--- IPv4 ---${plain}"
    echo "$ipip_v4_links" | while read -r t; do
      local local_ip=$(ip tunnel show "$t" 2>/dev/null | grep -Eo 'local ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}')
      local remote_ip=$(ip tunnel show "$t" 2>/dev/null | grep -Eo 'remote ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}')
      local tun_ip=$(ip -4 addr show dev "$t" | awk '/inet /{print $2}' | cut -d/ -f1)
      echo -e " ${green}$t${plain} local=$local_ip remote=$remote_ip vip=$tun_ip"
    done
  fi
  if [[ -n "$ipip_v6_links" ]]; then
    echo -e "${green}--- IPv6 ---${plain}"
    echo "$ipip_v6_links" | while read -r t; do
      local local_ip=$(ip -6 tunnel show "$t" 2>/dev/null | grep -Eo 'local ([0-9a-fA-F:]+)' | awk '{print $2}')
      local remote_ip=$(ip -6 tunnel show "$t" 2>/dev/null | grep -Eo 'remote ([0-9a-fA-F:]+)' | awk '{print $2}')
      local tun_ip=$(ip -6 addr show dev "$t" | awk '/inet6 /{print $2}' | cut -d/ -f1)
      echo -e " ${green}$t${plain} local=$local_ip remote=$remote_ip vip=$tun_ip"
    done
  fi
}

select_ipip_interface() {
  local names=()
  while IFS= read -r n; do names+=("$n"); done < <(ip -o link show type ipip | awk '{print $2}' | sed 's/://g;s/@NONE//g')
  while IFS= read -r n; do names+=("$n"); done < <(ip -o link show type ip6tnl | awk '{print $2}' | sed 's/://g;s/@NONE//g')
  [[ ${#names[@]} -gt 0 ]] || { echo -e "${red}未检测到 IPIP 接口。${plain}" >&2; return 1; }
  PS3="请选择要操作的 IPIP 隧道接口 (输入数字): "
  local sel
  select sel in "${names[@]}"; do
    [[ -n "$sel" ]] && echo "$sel" && return 0 || echo -e "${red}无效选择。${plain}" >&2
  done
}

reboot_ipip_interface() {
  clear
  echo -e "${blue}--- 重建/重启 IPIP 接口（调用 keeper） ---${plain}"
  local tun=$(select_ipip_interface) || return
  echo -e "${yellow}调用 keeper 进行一次性自愈：${tun}${plain}"
  systemctl start "ipip-ddns@${tun}.service" && echo -e "${green}已触发自愈。${plain}" || echo -e "${red}触发失败，请检查 env 与日志。${plain}"
  echo -e "${yellow}查看日志：journalctl -u ipip-ddns@${tun}.service -b | tail -n 50${plain}"
}

uninstall_ipip_interface() {
  clear
  echo -e "${blue}--- 卸载 IPIP 接口 ---${plain}"
  local tun=$(select_ipip_interface) || return
  read -p "警告: 卸载 ${tun} 会中断其网络。继续? (Y/N): " c
  [[ "$c" =~ ^[Yy]$ ]] || { echo -e "${yellow}已取消。${plain}"; return; }
  systemctl disable --now "ipip-ddns@${tun}.timer" >/dev/null 2>&1 || true
  rm -f "${ddns_conf_dir}/${tun}.env" >/dev/null 2>&1 || true
  ip link set "$tun" down &>/dev/null
  ip tunnel del "$tun" &>/dev/null
  ip -6 tunnel del "$tun" &>/dev/null
  echo -e "${green}接口 ${tun} 已卸载。${plain}"
}

manage_ipip_services() {
  clear
  echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}IPIP 隧道服务管理${plain}                                      ${green}║${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}    ${green}1.${plain} 查看所有 IPIP 接口 (IPv4/IPv6)                      ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}2.${plain} 重建/重启 IPIP 接口 (调用 keeper 自愈)              ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}3.${plain} 卸载 IPIP 接口                                      ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}    ${red}0.${plain} 返回主菜单                                          ${green}║${plain}"
  echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
  echo ""
  echo -ne "${yellow}请输入选项 [0-3]: ${plain}"
  read ipip_num
  case "$ipip_num" in
    0) return ;;
    1) 
      view_ipip_interfaces
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_ipip_services
      ;;
    2) 
      reboot_ipip_interface
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_ipip_services
      ;;
    3) 
      uninstall_ipip_interface
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_ipip_services
      ;;
    *) 
      echo -e "${red}❌ 无效输入，请重新选择！${plain}"
      sleep 1
      manage_ipip_services
      ;;
  esac
}

# =========================================================
# 安装IPIP IPv4（始终启用 keeper）
# =========================================================
install_ipip(){
  local ddnsname tunname vip_cidr vip remotevip netcardname localip remoteip
  echo -e "${blue}--- 正在部署 IPIPv4 隧道 (keeper 持久化) ---${plain}"
  
  # 输入 tunnel 名称
  echo -ne "${yellow}请输入要创建的tun网卡名称(例如 ipip)：${plain}"; read tunname
  [[ -z "$tunname" ]] && { echo -e "${red}tun网卡名称不能为空${plain}"; exit 1; }
  
  # 验证接口名称（防止命令注入）
  if [[ ! "$tunname" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo -e "${red}接口名只能包含字母、数字、下划线和连字符${plain}"
    exit 1
  fi
  
  # 检查是否已存在同名接口
  if ip link show "$tunname" &>/dev/null; then
    echo -e "${red}接口 ${tunname} 已存在${plain}"
    echo -e "${yellow}如需重新创建，请先卸载现有接口${plain}"
    exit 1
  fi
  
  if ! lsmod | grep -q ipip; then modprobe ipip && echo -e "${green}已加载 ipip 模块。${plain}"; fi
  if ! command -v dig &> /dev/null; then
    echo -e "${blue}正在安装 dnsutils (dig)...${plain}"
    if command -v apt-get &>/dev/null; then apt-get update >/dev/null 2>&1; apt-get install -y dnsutils >/dev/null 2>&1; else yum install -y bind-utils >/dev/null 2>&1; fi
  fi
  if ! command -v iptables &> /dev/null; then
    echo -e "${blue}正在安装 iptables...${plain}"
    if command -v apt-get &>/dev/null; then apt-get update >/dev/null 2>&1; apt-get install -y iptables >/dev/null 2>&1; else yum install -y iptables >/dev/null 2>&1; fi
  fi

  echo -ne "${yellow}请输入对端设备的ddns域名或者IP：${plain}"; read ddnsname
  echo -ne "${yellow}请输入本机隧道IP (如 192.168.100.2/30)：${plain}"; read vip_cidr
  [[ "$vip_cidr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || { echo -e "${red}无效IPv4 CIDR${plain}"; exit 1; }
  vip=$(echo "$vip_cidr" | cut -d/ -f1)
  echo -ne "${yellow}请输入对端IP (如 192.168.100.1)：${plain}"; read remotevip

  netcardname=$(get_main_interface)
  [[ -n "$netcardname" ]] || { echo -ne "${yellow}主网卡 (如 eth0): ${plain}"; read netcardname; [[ -z "$netcardname" ]] && { echo -e "${red}未输入主网卡。${plain}"; exit 1; }; }

  localip=$(ip -4 addr show dev "$netcardname" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
  [[ -n "$localip" ]] || { echo -ne "${yellow}请输入本机公网 IP: ${plain}"; read localip; [[ -z "$localip" ]] && { echo -e "${red}未输入公网 IP。${plain}"; exit 1; }; }

  remoteip="$ddnsname"
  if ! echo "$ddnsname" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    remoteip=$(getent hosts "$ddnsname" | awk '{print $1}' | grep -E '^[0-9.]+' | head -n1)
    [[ -z "$remoteip" ]] && remoteip=$(dig +short A "$ddnsname" | head -n1)
    [[ -z "$remoteip" ]] && remoteip=$(ping -4 -c1 "$ddnsname" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    [[ -z "$remoteip" ]] && { echo -e "${red}无法解析对端 IP。${plain}"; exit 1; }
    echo -e "${green}解析到对端 IP: ${remoteip}${plain}"
  fi

  install_ddns_keeper "$tunname" "v4" "$ddnsname" "$localip" "$vip_cidr" "$remotevip"

  # 清理可能存在的旧接口
  ip link show "$tunname" &>/dev/null && ip link set "$tunname" down &>/dev/null || true
  ip tunnel del "$tunname" &>/dev/null || true
  
  # 创建隧道（添加错误检查）
  if ! ip tunnel add "$tunname" mode ipip remote "${remoteip}" local "${localip}" ttl 64; then
    echo -e "${red}创建 IPIP 隧道失败，请检查网络配置${plain}"
    exit 1
  fi
  
  # 配置 IP 地址
  if ! ip addr add "${vip_cidr}" dev "$tunname" 2>/dev/null; then
    echo -e "${yellow}警告: IP 地址可能已存在，继续...${plain}"
  fi
  
  # 启动接口
  if ! ip link set "$tunname" up; then
    echo -e "${red}启动接口失败${plain}"
    ip tunnel del "$tunname" &>/dev/null
    exit 1
  fi
  
  # 添加路由
  ip route replace "${remotevip}/32" dev "$tunname" scope link src "${vip}" 2>/dev/null || true

  if ! iptables -w -t nat -C POSTROUTING -s "${remotevip}" -j MASQUERADE 2>/dev/null; then
    iptables -w -t nat -A POSTROUTING -s "${remotevip}" -j MASQUERADE
  fi
  if ! sysctl net.ipv4.ip_forward | grep -q " = 1"; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf &>/dev/null
  fi

  echo -e "${green}IPIP 隧道 ${tunname} 已创建并启用（keeper 持久化已开启）。${plain}"
  show_ping_reminder "$remotevip" "ipip"
}

# =========================================================
# 安装IPIP IPv6（始终启用 keeper）
# =========================================================
install_ipipv6(){
  local ddnsname tunname vip_cidr vip remotevip netcardname localip6 remoteip
  echo -e "${blue}--- 正在部署 IPIPv6 隧道 (keeper 持久化) ---${plain}"
  
  # 输入 tunnel 名称
  echo -ne "${yellow}请输入要创建的tun网卡名称(例如 ipip6)：${plain}"; read tunname
  [[ -z "$tunname" ]] && { echo -e "${red}tun网卡名称不能为空${plain}"; exit 1; }
  
  # 验证接口名称（防止命令注入）
  if [[ ! "$tunname" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo -e "${red}接口名只能包含字母、数字、下划线和连字符${plain}"
    exit 1
  fi
  
  # 检查是否已存在同名接口
  if ip link show "$tunname" &>/dev/null; then
    echo -e "${red}接口 ${tunname} 已存在${plain}"
    echo -e "${yellow}如需重新创建，请先卸载现有接口${plain}"
    exit 1
  fi
  
  if ! lsmod | grep -q ip6_tunnel; then modprobe ip6_tunnel && echo -e "${green}已加载 ip6_tunnel 模块。${plain}"; fi

  echo -ne "${yellow}请输入对端设备的ddns域名或者IP (IPv6)：${plain}"; read ddnsname
  echo -ne "${yellow}请输入本机隧道IP (如 fdef:1::1/64)：${plain}"; read vip_cidr
  [[ "$vip_cidr" =~ ^([0-9a-fA-F:]+/[0-9]{1,3})$ ]] || { echo -e "${red}无效IPv6 CIDR${plain}"; exit 1; }
  vip=$(echo "$vip_cidr" | cut -d/ -f1)
  echo -ne "${yellow}请输入对端IP (如 fdef:1::2)：${plain}"; read remotevip

  netcardname=$(get_main_interface)
  [[ -n "$netcardname" ]] || { echo -ne "${yellow}主网卡 (如 eth0): ${plain}"; read netcardname; [[ -z "$netcardname" ]] && { echo -e "${red}未输入主网卡。${plain}"; exit 1; }; }

  localip6=$(ip -6 addr show dev "$netcardname" scope global | awk '/inet6 /{print $2}' | cut -d/ -f1 | head -n1)
  [[ -n "$localip6" ]] || { echo -ne "${yellow}请输入本机IPv6公网 IP: ${plain}"; read localip6; [[ -z "$localip6" ]] && { echo -e "${red}未输入IPv6 公网 IP。${plain}"; exit 1; }; }

  remoteip="$ddnsname"
  if ! echo "$ddnsname" | grep -Eq '^[0-9a-fA-F:]+$'; then
    remoteip=$(getent hosts "$ddnsname" | awk '{print $1}' | grep -E '^[0-9a-fA-F:]+' | head -n1)
    [[ -z "$remoteip" ]] && remoteip=$(dig +short AAAA "$ddnsname" | head -n1)
    [[ -z "$remoteip" ]] && remoteip=$(ping6 -c1 "$ddnsname" 2>/dev/null | grep -Eo '([0-9a-fA-F:]+)' | head -n1)
    [[ -z "$remoteip" ]] && { echo -e "${red}无法解析对端 IPv6。${plain}"; exit 1; }
    echo -e "${green}解析到对端 IPv6: ${remoteip}${plain}"
  fi

  install_ddns_keeper "$tunname" "v6" "$ddnsname" "$localip6" "$vip_cidr" "$remotevip"

  # 清理可能存在的旧接口
  ip link show "$tunname" &>/dev/null && ip link set "$tunname" down &>/dev/null || true
  ip -6 tunnel del "$tunname" &>/dev/null || true
  
  # 创建 IPv6 隧道（添加错误检查）
  if ! ip link add name "$tunname" type ip6tnl local "${localip6}" remote "${remoteip}" mode any; then
    echo -e "${red}创建 IPIPv6 隧道失败，请检查网络配置${plain}"
    exit 1
  fi
  
  # 配置 IPv6 地址
  if ! ip -6 addr add "${vip_cidr}" dev "$tunname" 2>/dev/null; then
    echo -e "${yellow}警告: IPv6 地址可能已存在，继续...${plain}"
  fi
  
  # 启动接口
  if ! ip link set "$tunname" up; then
    echo -e "${red}启动接口失败${plain}"
    ip -6 tunnel del "$tunname" &>/dev/null
    exit 1
  fi

  if ! ip6tables -w -t nat -C POSTROUTING -s "${remotevip}" -j MASQUERADE 2>/dev/null; then
    ip6tables -w -t nat -A POSTROUTING -s "${remotevip}" -j MASQUERADE
  fi
  if ! sysctl net.ipv6.conf.all.forwarding | grep -q " = 1"; then
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf &>/dev/null
  fi

  echo -e "${green}IPIPv6 隧道 ${tunname} 已创建并启用（keeper 持久化已开启）。${plain}"
  show_ping_reminder "$remotevip" "ipipv6"
}

# =========================================================
# WireGuard 管理函数
# =========================================================
view_wg_interfaces() {
  clear
  echo -e "${blue}--- 已部署的 WireGuard 接口 ---${plain}"
  local active_wg_interfaces=$(wg show interfaces 2>/dev/null)
  local all_wg_config_files=(/etc/wireguard/*.conf)
  if [[ -z "$active_wg_interfaces" && "${all_wg_config_files[0]}" == "/etc/wireguard/*.conf" ]]; then
    echo -e "${yellow}未检测到任何 WireGuard 接口或配置文件。${plain}"; return; fi
  if [[ -n "$active_wg_interfaces" ]]; then
    echo -e "${green}--- 正在运行的 WireGuard 接口 ---${plain}"
    echo "$active_wg_interfaces" | tr ' ' '\n' | while read -r iface; do
      [[ -n "$iface" ]] && echo -e "--- 接口: ${green}$iface${plain} ---" && wg show "$iface" && echo ""
    done
  fi
  if [[ "${all_wg_config_files[0]}" != "/etc/wireguard/*.conf" ]]; then
    echo -e "${green}--- 所有配置 (/etc/wireguard/*.conf) ---${plain}"
    for config_file in "${all_wg_config_files[@]}"; do
      local iface_name=$(basename "$config_file" .conf)
      echo "$active_wg_interfaces" | grep -q "\<$iface_name\>" || echo -e " ${yellow}配置文件: ${config_file} (未运行)${plain}"
    done
  fi
}

select_wg_interface() {
  local wg_config_files=(/etc/wireguard/*.conf) wg_list=()
  for config_file in "${wg_config_files[@]}"; do [[ -f "$config_file" ]] && wg_list+=("$(basename "$config_file" .conf)"); done
  [[ ${#wg_list[@]} -gt 0 ]] || { echo -e "${red}未找到任何 WireGuard 配置。${plain}" >&2; return 1; }
  PS3="请选择要操作的 WireGuard 接口 (输入数字): "
  local selected_choice
  select selected_choice in "${wg_list[@]}"; do
    [[ -n "$selected_choice" ]] && echo "$selected_choice" && return 0 || echo -e "${red}无效选择。${plain}" >&2
  done
}

reboot_wg_interface() {
  clear
  echo -e "${blue}--- 重启 WireGuard 接口 ---${plain}"
  local chosen_wg_iface=$(select_wg_interface); local select_status=$?
  [[ $select_status -ne 0 || -z "$chosen_wg_iface" ]] && { echo -e "${red}接口选择失败。${plain}"; return; }
  echo -e "${yellow}正在重启 ${chosen_wg_iface}...${plain}"
  wg-quick down "$chosen_wg_iface" &>/dev/null || echo -e "${yellow}down 可能失败，继续 up...${plain}"
  wg-quick up "$chosen_wg_iface" &>/dev/null && echo -e "${green}重启成功。${plain}" || echo -e "${red}重启失败。${plain}"
}

uninstall_wg_interface_internal() {
  local wg_iface="$1"; local config_file="/etc/wireguard/${wg_iface}.conf"
  wg-quick down "$wg_iface" &>/dev/null
  systemctl disable "wg-quick@${wg_iface}" &>/dev/null
  systemctl stop "wg-quick@${wg_iface}" &>/dev/null
  [[ -f "$config_file" ]] && rm "$config_file" && echo -e "${blue}已删除配置 ${config_file}${plain}"
  echo -e "${green}WireGuard 接口 ${wg_iface} 已卸载。${plain}"
}

uninstall_wg_interface() {
  clear
  echo -e "${blue}--- 卸载 WireGuard 接口 ---${plain}"
  local chosen_wg_iface=$(select_wg_interface)
  local select_status=$?
  [[ $select_status -ne 0 || -z "$chosen_wg_iface" ]] && { echo -e "${red}接口选择失败。${plain}"; return; }
  read -p "确定卸载 ${chosen_wg_iface} ? (Y/N): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo -e "${yellow}已取消。${plain}"; return; }
  uninstall_wg_interface_internal "$chosen_wg_iface"
}

manage_wg_services() {
  clear
  echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}WireGuard 隧道服务管理${plain}                                 ${green}║${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}    ${green}1.${plain} 查看所有 WireGuard 接口                             ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}2.${plain} 重启 WireGuard 接口                                 ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}3.${plain} 卸载 WireGuard 接口                                 ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}    ${red}0.${plain} 返回主菜单                                          ${green}║${plain}"
  echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
  echo ""
  echo -ne "${yellow}请输入选项 [0-3]: ${plain}"
  read wg_num
  case "$wg_num" in
    0) return ;;
    1) 
      view_wg_interfaces
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_wg_services
      ;;
    2) 
      reboot_wg_interface
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_wg_services
      ;;
    3) 
      uninstall_wg_interface
      echo ""
      echo -ne "${green}按任意键返回...${plain}"
      read 
      manage_wg_services
      ;;
    *) 
      echo -e "${red}❌ 无效输入，请重新选择！${plain}"
      sleep 1
      manage_wg_services
      ;;
  esac
}

install_wg(){
  local filename local_wg_cidr local_wg_ip remote_wg_ip remote_wg_publickey wgport remote_wg_ipip_endpoint_ip endpoint_str privatekey_path publickey_path localprivatekey config_file
  echo -e "${blue}--- 正在部署 WireGuard 隧道 ---${plain}"
  
  # 检查并安装 WireGuard
  if ! command -v wg &> /dev/null; then
    echo -e "${yellow}正在安装 WireGuard...${plain}"
    check_sys
    if [[ ${release} == "centos" ]]; then
      if ! yum install -y epel-release 2>/dev/null; then
        echo -e "${yellow}尝试安装 EPEL 仓库...${plain}"
        yum install -y epel-release || echo -e "${yellow}EPEL 安装失败，继续尝试...${plain}"
      fi
      if ! yum install -y wireguard-tools 2>&1; then
        echo -e "${red}WireGuard 安装失败，请检查:${plain}"
        echo -e "${yellow}CentOS 可能需要启用 elrepo 仓库或使用其他方式安装${plain}"
        echo -e "${yellow}可以尝试: curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo${plain}"
        exit 1
      fi
    else
      apt-get update >/dev/null 2>&1
      if ! apt-get install -y wireguard wireguard-tools 2>&1; then
        echo -e "${red}WireGuard 安装失败${plain}"
        echo -e "${yellow}Debian/Ubuntu 可能需要启用 backports 仓库${plain}"
        exit 1
      fi
    fi
    if ! command -v wg &>/dev/null; then
      echo -e "${red}WireGuard 安装后仍无法找到 wg 命令${plain}"
      exit 1
    fi
    echo -e "${green}WireGuard 安装成功${plain}"
  fi
  
  # 检查并加载内核模块
  if ! lsmod | grep -q wireguard; then
    echo -e "${yellow}正在加载 WireGuard 内核模块...${plain}"
    modprobe wireguard 2>/dev/null || echo -e "${yellow}警告: 无法加载 wireguard 模块，可能需要安装 wireguard-dkms${plain}"
  fi
  
  # 创建密钥目录
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard
  
  privatekey_path="/etc/wireguard/privatekey"
  publickey_path="/etc/wireguard/publickey"
  if [[ ! -f $privatekey_path ]]; then
    echo -e "${yellow}正在生成密钥对...${plain}"
    wg genkey | tee $privatekey_path | wg pubkey | tee $publickey_path
    chmod 600 $privatekey_path $publickey_path
    echo -e "${green}密钥对已生成${plain}"
  fi
  localprivatekey=$(cat $privatekey_path)
  
  # 输入配置信息
  echo -ne "${yellow}接口名 (如 wg0): ${plain}"; read filename
  [[ -z "$filename" ]] && { echo -e "${red}接口名不能为空${plain}"; exit 1; }
  
  # 验证接口名称（防止命令注入）
  if [[ ! "$filename" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo -e "${red}接口名只能包含字母、数字、下划线和连字符${plain}"
    exit 1
  fi
  config_file="/etc/wireguard/${filename}.conf"
  [[ -f "$config_file" ]] && { echo -e "${red}配置文件已存在: ${config_file}${plain}"; echo -e "${yellow}如需覆盖，请先卸载现有接口${plain}"; exit 1; }
  
  echo -ne "${yellow}本机内网 CIDR (如 10.0.0.2/24 或 fdf1::2/64): ${plain}"; read local_wg_cidr
  [[ -z "$local_wg_cidr" ]] && { echo -e "${red}CIDR 不能为空${plain}"; exit 1; }
  if echo "$local_wg_cidr" | grep -q ':'; then
    [[ "$local_wg_cidr" =~ ^([0-9a-fA-F:]+/[0-9]{1,3})$ ]] || { echo -e "${red}无效IPv6 CIDR: ${local_wg_cidr}${plain}"; exit 1; }
  else
    [[ "$local_wg_cidr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || { echo -e "${red}无效IPv4 CIDR: ${local_wg_cidr}${plain}"; exit 1; }
  fi
  local_wg_ip=$(echo "$local_wg_cidr" | cut -d/ -f1)
  
  echo -ne "${yellow}对端内网 IP (如 10.0.0.1 或 fdf1::1): ${plain}"; read remote_wg_ip
  [[ -z "$remote_wg_ip" ]] && { echo -e "${red}对端 IP 不能为空${plain}"; exit 1; }
  
  echo -e "${yellow}请输入对端公钥（WireGuard 公钥，通常为 44 字符）:${plain}"
  echo -e "${yellow}提示: 可以直接粘贴，脚本会自动去除空格和换行符${plain}"
  
  # 循环输入公钥，直到输入正确或用户取消
  while true; do
    echo -ne "${yellow}对端公钥: ${plain}"; read remote_wg_publickey_input
    
    # 去除所有空格、换行符和制表符
    remote_wg_publickey=$(echo "$remote_wg_publickey_input" | tr -d '[:space:]')
    
    # 检查是否为空
    if [[ -z "$remote_wg_publickey" ]]; then
      echo -e "${red}✗ 对端公钥不能为空${plain}"
      echo -e "${yellow}请重新输入，或按 Ctrl+C 取消${plain}"
      echo ""
      continue
    fi
    
    # WireGuard 公钥验证（base64 编码，通常 40-44 字符）
    local key_len=${#remote_wg_publickey}
    
    # 检查长度
    if [[ $key_len -lt 40 ]] || [[ $key_len -gt 44 ]]; then
      echo -e "${red}✗ 公钥长度不正确（当前: ${key_len} 字符，应为 40-44 字符）${plain}"
      echo -e "${yellow}请检查公钥是否正确复制，或按 Ctrl+C 取消${plain}"
      echo ""
      continue
    fi
    
    # 检查是否为有效的 base64 字符
    if ! echo "$remote_wg_publickey" | grep -qE '^[A-Za-z0-9+/=]+$'; then
      echo -e "${red}✗ 公钥格式不正确（包含非法字符）${plain}"
      echo -e "${yellow}公钥应只包含 base64 字符: A-Z, a-z, 0-9, +, /, =${plain}"
      echo -e "${yellow}请重新输入，或按 Ctrl+C 取消${plain}"
      echo ""
      continue
    fi
    
    # 验证通过，退出循环
    echo -e "${green}✓ 公钥格式验证通过（长度: ${key_len} 字符）${plain}"
    break
  done
  
  echo -ne "${yellow}监听端口 (1-65535): ${plain}"; read wgport
  [[ "$wgport" =~ ^[0-9]+$ ]] && [ "$wgport" -ge 1 ] && [ "$wgport" -le 65535 ] || { echo -e "${red}无效端口: ${wgport}${plain}"; exit 1; }
  
  echo -ne "${yellow}Endpoint (对端 IPIP 内部 IP，如 192.168.100.1 / fdef:1::2): ${plain}"; read remote_wg_ipip_endpoint_ip
  [[ -z "$remote_wg_ipip_endpoint_ip" ]] && { echo -e "${red}Endpoint 不能为空${plain}"; exit 1; }
  
  endpoint_str="${remote_wg_ipip_endpoint_ip}:${wgport}"
  echo "$remote_wg_ipip_endpoint_ip" | grep -q ':' && endpoint_str="[${remote_wg_ipip_endpoint_ip}]:${wgport}"
  
  local post_up_cmds=""
  local post_down_cmds=""
  local main_net_iface=""
  
  # 自动开启 NAT 转发 (VPN 网关功能)
  echo -e "${green}正在自动配置 NAT 转发 (VPN 网关)...${plain}"
  
  # 兼容性更好的主网卡检测方法
  main_net_iface=$(get_main_interface)
  [[ -z "$main_net_iface" ]] && { echo -ne "${yellow}主网卡 (如 eth0): ${plain}"; read main_net_iface; }
  [[ -z "$main_net_iface" ]] && { echo -e "${red}主网卡不能为空${plain}"; exit 1; }
  
  echo -e "${green}检测到主网卡: ${main_net_iface}${plain}"
  
  if echo "$local_wg_cidr" | grep -q ':'; then
    # IPv6 NAT (需要 ip6tables)
    if command -v ip6tables &>/dev/null; then
      post_up_cmds="PostUp = ip6tables -w -A FORWARD -i %i -j ACCEPT; ip6tables -w -t nat -A POSTROUTING -o ${main_net_iface} -j MASQUERADE"
      post_down_cmds="PostDown = ip6tables -w -D FORWARD -i %i -j ACCEPT; ip6tables -w -t nat -D POSTROUTING -o ${main_net_iface} -j MASQUERADE"
      echo -e "${green}✓ IPv6 NAT 转发已配置${plain}"
    else
      echo -e "${yellow}警告: 未找到 ip6tables，IPv6 NAT 功能可能不可用${plain}"
    fi
    sysctl net.ipv6.conf.all.forwarding | grep -q " = 1" || { echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf; sysctl -p /etc/sysctl.conf &>/dev/null; }
  else
    # IPv4 NAT
    if command -v iptables &>/dev/null; then
      post_up_cmds="PostUp = iptables -w -A FORWARD -i %i -j ACCEPT; iptables -w -t nat -A POSTROUTING -o ${main_net_iface} -j MASQUERADE"
      post_down_cmds="PostDown = iptables -w -D FORWARD -i %i -j ACCEPT; iptables -w -t nat -D POSTROUTING -o ${main_net_iface} -j MASQUERADE"
      echo -e "${green}✓ IPv4 NAT 转发已配置${plain}"
    else
      echo -e "${yellow}警告: 未找到 iptables，IPv4 NAT 功能可能不可用${plain}"
    fi
    sysctl net.ipv4.ip_forward | grep -q " = 1" || { echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf; sysctl -p /etc/sysctl.conf &>/dev/null; }
  fi
  
  if echo "$remote_wg_ip" | grep -q ':'; then
    allowed_ips="${remote_wg_ip}/128"
  else
    allowed_ips="${remote_wg_ip}/32"
  fi
  
  # 生成配置文件
  echo -e "${yellow}正在生成配置文件...${plain}"
  cat > "$config_file" <<EOF
[Interface]
Address = ${local_wg_cidr}
ListenPort = ${wgport}
PrivateKey = ${localprivatekey}
MTU = 1420
${post_up_cmds}
${post_down_cmds}

[Peer]
PublicKey = ${remote_wg_publickey}
AllowedIPs = ${allowed_ips}
Endpoint = ${endpoint_str}
PersistentKeepalive = 25
EOF
  chmod 600 "$config_file"
  echo -e "${green}配置文件已创建: ${config_file}${plain}"
  echo -e "${yellow}注意: 配置文件包含私钥，已设置为仅 root 可读 (权限 600)${plain}"
  
  # 启动 WireGuard
  echo -e "${yellow}正在启动 WireGuard 接口...${plain}"
  local wg_start_output
  wg_start_output=$(wg-quick up "$filename" 2>&1)
  local wg_start_status=$?
  
  if [[ $wg_start_status -eq 0 ]]; then
    echo -e "${green}WireGuard 接口启动成功${plain}"
  else
    echo -e "${red}✗ wg-quick up 失败（退出码: $wg_start_status）${plain}"
    echo ""
    echo -e "${red}错误信息:${plain}"
    echo "$wg_start_output" | tail -n 10
    echo ""
    echo -e "${yellow}配置文件内容（供检查）:${plain}"
    echo -e "${blue}----------------------------------------${plain}"
    cat "$config_file"
    echo -e "${blue}----------------------------------------${plain}"
    echo ""
    echo -e "${yellow}可能的原因:${plain}"
    echo -e "  1. 对端公钥格式错误或长度不正确"
    echo -e "  2. Endpoint 地址无法访问或格式错误"
    echo -e "  3. 监听端口被占用"
    echo -e "  4. 网络配置问题（IP 冲突等）"
    exit 1
  fi
  
  # 配置开机自启
  systemctl enable "wg-quick@${filename}" &>/dev/null
  if systemctl is-enabled "wg-quick@${filename}" &>/dev/null; then
    echo -e "${green}开机自启已启用${plain}"
  else
    echo -e "${yellow}警告: 无法启用开机自启${plain}"
  fi
  
  # 检查接口是否实际运行（wg-quick 是 oneshot 服务，启动后会退出）
  # 所以不能使用 systemctl is-active 检查，应该直接检查 wg 接口是否运行
  sleep 1
  if wg show "$filename" &>/dev/null; then
    echo -e "${green}✓ ${filename} 接口已启动并运行正常${plain}"
    echo ""
    echo -e "${blue}=== WireGuard 接口信息 ===${plain}"
    wg show "$filename"
    echo ""
    echo -e "${yellow}本机公钥:${plain}"
    cat "$publickey_path"
    echo ""
  else
    echo -e "${red}✗ 接口启动失败或未运行${plain}"
    echo -e "${yellow}查看详细日志: journalctl -u wg-quick@${filename} -n 50${plain}"
    exit 1
  fi
  
  echo -e "${green}WireGuard 部署完成！${plain}"
  echo -e "${yellow}快速诊断命令: wg show ${filename}${plain}"
  show_ping_reminder "$remote_wg_ip" "wireguard"
}

# =========================================================
# Gost 管理函数
# =========================================================
Installation_dependency() {
  if ! command -v gzip &> /dev/null || ! command -v jq &> /dev/null; then
    check_sys
    if [[ ${release} == "centos" ]]; then
      yum update -y
      yum install -y gzip wget jq
    else
      apt-get update >/dev/null 2>&1
      apt-get install -y gzip wget jq
    fi
  fi
}

check_file() {
  [[ -d /usr/lib/systemd/system ]] || { mkdir -p /usr/lib/systemd/system; chmod 755 /usr/lib/systemd/system; }
}

check_nor_file() {
  rm -rf ./gost ./gost.service ./config.json
  rm -rf /etc/gost /usr/lib/systemd/system/gost.service /usr/bin/gost
}

function checknew() {
  local current_ver=$(gost -V 2>&1 | awk '{print $2}')
  echo "你的gost版本为: ${current_ver}"
  echo -n "是否更新(y/n): "
  read checknewnum
  if test "$checknewnum" = "y"; then
    cp -r /etc/gost /tmp/
    Install_ct
    rm -rf /etc/gost
    mv /tmp/gost /etc/
    systemctl restart gost
  else
    exit 0
  fi
}

function Install_ct() {
  check_root
  check_nor_file
  Installation_dependency
  check_file
  check_sys
  echo -e "若为国内机器建议使用大陆镜像加速下载"
  read -e -p "是否使用？[y/n]:" addyn
  [[ -z ${addyn} ]] && addyn="n"
  if [[ ${addyn} == [Yy] ]]; then
    rm -rf gost-linux-"$bit"-"$ct_new_ver".gz
    wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost-linux-"$bit"-"$ct_new_ver".gz
    gunzip gost-linux-"$bit"-"$ct_new_ver".gz
    mv gost-linux-"$bit"-"$ct_new_ver" gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://gotunnel.oss-cn-shenzhen.aliyuncs.com/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  else
    rm -rf gost-linux-"$bit"-"$ct_new_ver".gz
    wget --no-check-certificate https://github.com/ginuerzh/gost/releases/download/v"$ct_new_ver"/gost-linux-"$bit"-"$ct_new_ver".gz
    gunzip gost-linux-"$bit"-"$ct_new_ver".gz
    mv gost-linux-"$bit"-"$ct_new_ver" gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  fi

  systemctl enable gost && systemctl restart gost
  echo "------------------------------"
  if test -a /usr/bin/gost -a /usr/lib/systemd/system/gost.service -a /etc/gost/config.json; then
    echo "gost安装成功"
    rm -rf "$(pwd)"/gost
    rm -rf "$(pwd)"/gost.service
    rm -rf "$(pwd)"/config.json
  else
    echo "gost没有安装成功"
    rm -rf "$(pwd)"/gost
    rm -rf "$(pwd)"/gost.service
    rm -rf "$(pwd)"/config.json
    rm -rf "$(pwd)"/gost.sh
  fi
}

function Uninstall_ct() {
  rm -rf /usr/bin/gost
  rm -rf /usr/lib/systemd/system/gost.service
  rm -rf /etc/gost
  rm -rf "$(pwd)"/gost.sh
  echo "gost已经成功删除"
}

function Start_ct() {
  systemctl start gost
  echo "已启动"
}

function Stop_ct() {
  systemctl stop gost
  echo "已停止"
}

function Restart_ct() {
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo "已重读配置并重启"
}

function read_protocol() {
  echo -e "请问您要设置哪种功能: "
  echo -e "-----------------------------------"
  echo -e "[1] tcp+udp流量转发, 不加密"
  echo -e "说明: 一般设置在国内中转机上"
  echo -e "-----------------------------------"
  echo -e "[2] 加密隧道流量转发"
  echo -e "说明: 用于转发原本加密等级较低的流量, 一般设置在国内中转机上"
  echo -e "     选择此协议意味着你还有一台机器用于接收此加密流量, 之后须在那台机器上配置协议[3]进行对接"
  echo -e "-----------------------------------"
  echo -e "[3] 解密由gost传输而来的流量并转发"
  echo -e "说明: 对于经由gost加密中转的流量, 通过此选项进行解密并转发给本机的代理服务端口或转发给其他远程机器"
  echo -e "      一般设置在用于接收中转流量的国外机器上"
  echo -e "-----------------------------------"
  echo -e "[4] 一键安装ss/socks5/http代理"
  echo -e "说明: 使用gost内置的代理协议，轻量且易于管理"
  echo -e "-----------------------------------"
  echo -e "[5] 进阶：多落地均衡负载"
  echo -e "说明: 支持各种加密方式的简单均衡负载"
  echo -e "-----------------------------------"
  echo -e "[6] 进阶：转发CDN自选节点"
  echo -e "说明: 只需在中转机设置"
  echo -e "-----------------------------------"
  read -p "请选择: " numprotocol

  if [ "$numprotocol" == "1" ]; then
    flag_a="nonencrypt"
  elif [ "$numprotocol" == "2" ]; then
    encrypt
  elif [ "$numprotocol" == "3" ]; then
    decrypt
  elif [ "$numprotocol" == "4" ]; then
    proxy
  elif [ "$numprotocol" == "5" ]; then
    enpeer
  elif [ "$numprotocol" == "6" ]; then
    cdn
  else
    echo "type error, please try again"
    exit
  fi
}

function read_s_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "-----------------------------------"
    read -p "请输入ss密码: " flag_b
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "请输入socks密码: " flag_b
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -p "请输入http密码: " flag_b
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机哪个端口接收到的流量进行转发?"
    read -p "请输入: " flag_b
  fi
}

function read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问您要设置的ss加密(仅提供常用的几种): "
    echo -e "-----------------------------------"
    echo -e "[1] aes-256-gcm"
    echo -e "[2] aes-256-cfb"
    echo -e "[3] chacha20-ietf-poly1305"
    echo -e "[4] chacha20"
    echo -e "[5] rc4-md5"
    echo -e "[6] AEAD_CHACHA20_POLY1305"
    echo -e "-----------------------------------"
    read -p "请选择ss加密方式: " ssencrypt

    if [ "$ssencrypt" == "1" ]; then
      flag_c="aes-256-gcm"
    elif [ "$ssencrypt" == "2" ]; then
      flag_c="aes-256-cfb"
    elif [ "$ssencrypt" == "3" ]; then
      flag_c="chacha20-ietf-poly1305"
    elif [ "$ssencrypt" == "4" ]; then
      flag_c="chacha20"
    elif [ "$ssencrypt" == "5" ]; then
      flag_c="rc4-md5"
    elif [ "$ssencrypt" == "6" ]; then
      flag_c="AEAD_CHACHA20_POLY1305"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "请输入socks用户名: " flag_c
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -p "请输入http用户名: " flag_c
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请输入落地列表文件名"
    read -e -p "自定义但不同配置应不重复，不用输入后缀，例如 ips1、iplist2: " flag_c
    touch $flag_c.txt
    echo -e "------------------------------------------------------------------"
    echo -e "请依次输入你要均衡负载的落地ip与端口"
    while true; do
      echo -e "请问你要将本机从${flag_b}接收到的流量转发向的IP或域名?"
      read -p "请输入: " peer_ip
      echo -e "请问你要将本机从${flag_b}接收到的流量转发向${peer_ip}的哪个端口?"
      read -p "请输入: " peer_port
      echo -e "$peer_ip:$peer_port" >>$flag_c.txt
      read -e -p "是否继续添加落地？[Y/n]:" addyn
      [[ -z ${addyn} ]] && addyn="y"
      if [[ ${addyn} == [Nn] ]]; then
        echo -e "------------------------------------------------------------------"
        echo -e "已在root目录创建$flag_c.txt，您可以随时编辑该文件修改落地信息，重启gost即可生效"
        echo -e "------------------------------------------------------------------"
        break
      else
        echo -e "------------------------------------------------------------------"
        echo -e "继续添加均衡负载落地配置"
      fi
    done
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "将本机从${flag_b}接收到的流量转发向的自选ip:"
    read -p "请输入: " flag_c
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
    echo -e "[1] 80"
    echo -e "[2] 443"
    echo -e "[3] 自定义端口（如8080等）"
    read -p "请选择端口: " cdnport
    if [ "$cdnport" == "1" ]; then
      flag_c="$flag_c:80"
    elif [ "$cdnport" == "2" ]; then
      flag_c="$flag_c:443"
    elif [ "$cdnport" == "3" ]; then
      read -p "请输入自定义端口: " customport
      flag_c="$flag_c:$customport"
    else
      echo "type error, please try again"
      exit
    fi
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向哪个IP或域名?"
    echo -e "注: IP既可以是[远程机器/当前机器]的公网IP, 也可是以本机本地回环IP(即127.0.0.1)"
    echo -e "具体IP地址的填写, 取决于接收该流量的服务正在监听的IP(详见: https://github.com/KANIKIG/Multi-EasyGost)"
    if [[ ${is_cert} == [Yy] ]]; then
      echo -e "注意: 落地机开启自定义tls证书，务必填写${Red_font_prefix}域名${Font_color_suffix}"
    fi
    read -p "请输入: " flag_c
  fi
}

function read_d_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置ss代理服务的端口?"
    read -p "请输入: " flag_d
  elif [ "$flag_a" == "socks" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置socks代理服务的端口?"
    read -p "请输入: " flag_d
  elif [ "$flag_a" == "http" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置http代理服务的端口?"
    read -p "请输入: " flag_d
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "您要设置的均衡负载策略: "
    echo -e "-----------------------------------"
    echo -e "[1] round - 轮询"
    echo -e "[2] random - 随机"
    echo -e "[3] fifo - 自上而下"
    echo -e "-----------------------------------"
    read -p "请选择均衡负载类型: " numstra

    if [ "$numstra" == "1" ]; then
      flag_d="round"
    elif [ "$numstra" == "2" ]; then
      flag_d="random"
    elif [ "$numstra" == "3" ]; then
      flag_d="fifo"
    else
      echo "type error, please try again"
      exit
    fi
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    read -p "请输入host:" flag_d
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
    read -p "请输入: " flag_d
    if [[ ${is_cert} == [Yy] ]]; then
      flag_d="$flag_d?secure=true"
    fi
  fi
}

function writerawconf() {
  echo $flag_a"/""$flag_b""#""$flag_c""#""$flag_d" >>$raw_conf_path
}

function rawconf() {
  read_protocol
  read_s_port
  read_d_ip
  read_d_port
  writerawconf
}

function eachconf_retrieve() {
  d_server=${trans_conf#*#}
  d_port=${d_server#*#}
  d_ip=${d_server%#*}
  flag_s_port=${trans_conf%%#*}
  s_port=${flag_s_port#*/}
  is_encrypt=${flag_s_port%/*}
}

function confstart() {
  echo "{
    \"Debug\": true,
    \"Retries\": 0,
    \"ServeNodes\": [" >>$gost_conf_path
}

function multiconfstart() {
  echo "        {
            \"Retries\": 0,
            \"ServeNodes\": [" >>$gost_conf_path
}

function conflast() {
  echo "    ]
}" >>$gost_conf_path
}

function multiconflast() {
  if [ $i -eq $count_line ]; then
    echo "            ]
        }" >>$gost_conf_path
  else
    echo "            ]
        }," >>$gost_conf_path
  fi
}

function encrypt() {
  echo -e "请问您要设置的转发传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls隧道"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  echo -e "-----------------------------------"
  read -p "请选择转发传输类型: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
    echo -e "注意: 选择 是 将针对落地的自定义证书开启证书校验保证安全性，稍后落地机务必填写${Red_font_prefix}域名${Font_color_suffix}"
    read -e -p "落地机是否开启了自定义tls证书？[y/n]:" is_cert
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
    echo -e "注意: 选择 是 将针对落地的自定义证书开启证书校验保证安全性，稍后落地机务必填写${Red_font_prefix}域名${Font_color_suffix}"
    read -e -p "落地机是否开启了自定义tls证书？[y/n]:" is_cert
  else
    echo "type error, please try again"
    exit
  fi
}

function enpeer() {
  echo -e "请问您要设置的均衡负载传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] tls隧道"
  echo -e "[3] ws隧道"
  echo -e "[4] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认同一配置的传输类型相同"
  echo -e "此脚本仅支持简单型均衡负载，具体可参考官方文档"
  echo -e "gost均衡负载官方文档：https://docs.ginuerzh.xyz/gost/load-balancing"
  echo -e "-----------------------------------"
  read -p "请选择转发传输类型: " numpeer

  if [ "$numpeer" == "1" ]; then
    flag_a="peerno"
  elif [ "$numpeer" == "2" ]; then
    flag_a="peertls"
  elif [ "$numpeer" == "3" ]; then
    flag_a="peerws"
  elif [ "$numpeer" == "4" ]; then
    flag_a="peerwss"
  else
    echo "type error, please try again"
    exit
  fi
}

function cdn() {
  echo -e "请问您要设置的CDN传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！"
  echo -e "此功能只需在中转机设置"
  echo -e "-----------------------------------"
  read -p "请选择CDN转发传输类型: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    echo "type error, please try again"
    exit
  fi
}

function cert() {
  echo -e "-----------------------------------"
  echo -e "[1] ACME一键申请证书"
  echo -e "[2] 手动上传证书"
  echo -e "-----------------------------------"
  echo -e "说明: 仅用于落地机配置，默认使用的gost内置的证书可能带来安全问题，使用自定义证书提高安全性"
  echo -e "     配置后对本机所有tls/wss解密生效，无需再次设置"
  read -p "请选择证书生成方式: " numcert

  if [ "$numcert" == "1" ]; then
    check_sys
    if [[ ${release} == "centos" ]]; then
      yum install -y socat
    else
      apt-get install -y socat
    fi
    read -p "请输入ZeroSSL的账户邮箱(至 zerossl.com 注册即可)：" zeromail
    read -p "请输入解析到本机的域名：" domain
    curl https://get.acme.sh | sh
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server zerossl
    "$HOME"/.acme.sh/acme.sh --register-account -m "${zeromail}" --server zerossl
    echo -e "ACME证书申请程序安装成功"
    echo -e "-----------------------------------"
    echo -e "[1] HTTP申请（需要80端口未占用）"
    echo -e "[2] Cloudflare DNS API 申请（需要输入APIKEY）"
    echo -e "-----------------------------------"
    read -p "请选择证书申请方式: " certmethod
    if [ "$certmethod" == "1" ]; then
      echo -e "请确认本机${Red_font_prefix}80${Font_color_suffix}端口未被占用, 否则会申请失败"
      if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL 证书生成成功，默认申请高安全性的ECC证书"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL 证书配置成功，且会自动续签，证书及秘钥位于用户目录下的 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录"
          echo -e "证书目录名与证书文件名请勿更改; 删除 gost_cert 目录后用脚本重启,即自动启用gost内置证书"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL 证书生成失败"
        exit 1
      fi
    else
      read -p "请输入Cloudflare账户邮箱：" cfmail
      read -p "请输入Cloudflare Global API Key：" cfkey
      export CF_Key="${cfkey}"
      export CF_Email="${cfmail}"
      if "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL 证书生成成功，默认申请高安全性的ECC证书"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL 证书配置成功，且会自动续签，证书及秘钥位于用户目录下的 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录"
          echo -e "证书目录名与证书文件名请勿更改; 删除 gost_cert 目录后使用脚本重启, 即重新启用gost内置证书"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL 证书生成失败"
        exit 1
      fi
    fi

  elif [ "$numcert" == "2" ]; then
    if [ ! -d "$HOME/gost_cert" ]; then
      mkdir $HOME/gost_cert
    fi
    echo -e "-----------------------------------"
    echo -e "已在用户目录建立 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录，请将证书文件 cert.pem 与秘钥文件 key.pem 上传到该目录"
    echo -e "证书与秘钥文件名必须与上述一致，目录名也请勿更改"
    echo -e "上传成功后，用脚本重启gost会自动启用，无需再设置; 删除 gost_cert 目录后用脚本重启,即重新启用gost内置证书"
    echo -e "-----------------------------------"
  else
    echo "type error, please try again"
    exit
  fi
}

function decrypt() {
  echo -e "请问您要设置的解密传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  echo -e "-----------------------------------"
  read -p "请选择解密传输类型: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    echo "type error, please try again"
    exit
  fi
}

function proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "请问您要设置的代理类型: "
  echo -e "-----------------------------------"
  echo -e "[1] shadowsocks"
  echo -e "[2] socks5(强烈建议加隧道用于Telegram代理)"
  echo -e "[3] http"
  echo -e "-----------------------------------"
  read -p "请选择代理类型: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  elif [ "$numproxy" == "3" ]; then
    flag_a="http"
  else
    echo "type error, please try again"
    exit
  fi
}

function method() {
  if [ $i -eq 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "        \"tcp://:$s_port/$d_ip:$d_port\",
        \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "        \"tcp://:$s_port/$d_ip?host=$d_port\",
        \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "        \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
        \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "        \"tcp://:$s_port\",
        \"udp://:$s_port\"
    ],
    \"ChainNodes\": [
        \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "        \"tcp://:$s_port\",
		  \"udp://:$s_port\"
	],
	\"ChainNodes\": [
		\"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  elif [ $i -gt 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "                \"tcp://:$s_port/$d_ip:$d_port\",
                \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "                \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
                \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "                \"tcp://:$s_port/$d_ip?host=$d_port\",
                \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "                \"tcp://:$s_port\",
	            \"udp://:$s_port\"
	        ],
	        \"ChainNodes\": [
	            \"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "                \"tcp://:$s_port\",
		        \"udp://:$s_port\"
		    ],
		    \"ChainNodes\": [
		        \"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "                 \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        		  \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  else
    echo "config error"
    exit
  fi
}

function writeconf() {
  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    if [ $i -eq 1 ]; then
      trans_conf=$(sed -n "${i}p" $raw_conf_path)
      eachconf_retrieve
      method
    elif [ $i -gt 1 ]; then
      if [ $i -eq 2 ]; then
        echo "    ],
    \"Routes\": [" >>$gost_conf_path
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      else
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      fi
    fi
  done
}

function show_all_conf() {
  echo -e "                      GOST 配置                        "
  echo -e "--------------------------------------------------------"
  echo -e "序号|方法\t    |本地端口\t|目的地地址:目的地端口"
  echo -e "--------------------------------------------------------"

  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    trans_conf=$(sed -n "${i}p" $raw_conf_path)
    eachconf_retrieve

    if [ "$is_encrypt" == "nonencrypt" ]; then
      str="不加密中转"
    elif [ "$is_encrypt" == "encrypttls" ]; then
      str=" tls隧道 "
    elif [ "$is_encrypt" == "encryptws" ]; then
      str="  ws隧道 "
    elif [ "$is_encrypt" == "encryptwss" ]; then
      str=" wss隧道 "
    elif [ "$is_encrypt" == "peerno" ]; then
      str=" 不加密均衡负载 "
    elif [ "$is_encrypt" == "peertls" ]; then
      str=" tls隧道均衡负载 "
    elif [ "$is_encrypt" == "peerws" ]; then
      str="  ws隧道均衡负载 "
    elif [ "$is_encrypt" == "peerwss" ]; then
      str=" wss隧道均衡负载 "
    elif [ "$is_encrypt" == "decrypttls" ]; then
      str=" tls解密 "
    elif [ "$is_encrypt" == "decryptws" ]; then
      str="  ws解密 "
    elif [ "$is_encrypt" == "decryptwss" ]; then
      str=" wss解密 "
    elif [ "$is_encrypt" == "ss" ]; then
      str="   ss   "
    elif [ "$is_encrypt" == "socks" ]; then
      str=" socks5 "
    elif [ "$is_encrypt" == "http" ]; then
      str=" http "
    elif [ "$is_encrypt" == "cdnno" ]; then
      str="不加密转发CDN"
    elif [ "$is_encrypt" == "cdnws" ]; then
      str="ws隧道转发CDN"
    elif [ "$is_encrypt" == "cdnwss" ]; then
      str="wss隧道转发CDN"
    else
      str=""
    fi

    echo -e " $i  |$str  |$s_port\t|$d_ip:$d_port"
    echo -e "--------------------------------------------------------"
  done
}

cron_restart() {
  echo -e "------------------------------------------------------------------"
  echo -e "gost定时重启任务: "
  echo -e "-----------------------------------"
  echo -e "[1] 配置gost定时重启任务"
  echo -e "[2] 删除gost定时重启任务"
  echo -e "-----------------------------------"
  read -p "请选择: " numcron
  if [ "$numcron" == "1" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "gost定时重启任务类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 每？小时重启"
    echo -e "[2] 每日？点重启"
    echo -e "-----------------------------------"
    read -p "请选择: " numcrontype
    if [ "$numcrontype" == "1" ]; then
      echo -e "-----------------------------------"
      read -p "每？小时重启: " cronhr
      echo "0 0 */$cronhr * * ? * systemctl restart gost" >>/etc/crontab
      echo -e "定时重启设置成功！"
    elif [ "$numcrontype" == "2" ]; then
      echo -e "-----------------------------------"
      read -p "每日？点重启: " cronhr
      echo "0 0 $cronhr * * ? systemctl restart gost" >>/etc/crontab
      echo -e "定时重启设置成功！"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$numcron" == "2" ]; then
    sed -i "/gost/d" /etc/crontab
    echo -e "定时重启任务删除完成！"
  else
    echo "type error, please try again"
    exit
  fi
}

update_sh() {
  # 静默检查版本更新（不提示用户，避免干扰）
  # 注意：这是整合版脚本，不检查原 gost.sh 的版本
  # 如需检查更新，请访问脚本所在仓库
  return 0
}

manage_gost_services() {
  clear
  echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}Gost 服务管理 v${shell_version}${plain}                                   ${green}║${plain}"
  echo -e "${green}║${plain}    ${yellow}支持多种转发协议和代理服务${plain}                             ${green}║${plain}"
  echo -e "${green}║${plain}                                                           ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}  ${white}【安装管理】${plain}                                             ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}1.${plain} 安装 Gost                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}2.${plain} 更新 Gost                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${green}3.${plain} 卸载 Gost                                           ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}  ${white}【服务控制】${plain}                                             ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}4.${plain} 启动 Gost                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}5.${plain} 停止 Gost                                           ${green}║${plain}"
  echo -e "${green}║${plain}    ${blue}6.${plain} 重启 Gost                                           ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}  ${white}【配置管理】${plain}                                             ${green}║${plain}"
  echo -e "${green}║${plain}    ${yellow}7.${plain} 新增转发配置 (tcp+udp/加密/解密/代理)               ${green}║${plain}"
  echo -e "${green}║${plain}    ${yellow}8.${plain} 查看现有配置                                        ${green}║${plain}"
  echo -e "${green}║${plain}    ${yellow}9.${plain} 删除转发配置                                        ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}  ${white}【高级功能】${plain}                                             ${green}║${plain}"
  echo -e "${green}║${plain}    ${white}10.${plain} 定时重启配置                                       ${green}║${plain}"
  echo -e "${green}║${plain}    ${white}11.${plain} 自定义 TLS 证书配置                                ${green}║${plain}"
  echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
  echo -e "${green}║${plain}    ${red}0.${plain} 返回主菜单                                          ${green}║${plain}"
  echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
  echo ""
  echo -ne "${yellow}请输入选项 [0-11]: ${plain}"
  read num
  case "$num" in
  1)
    Install_ct
    ;;
  2)
    checknew
    ;;
  3)
    Uninstall_ct
    ;;
  4)
    Start_ct
    ;;
  5)
    Stop_ct
    ;;
  6)
    Restart_ct
    ;;
  7)
    rawconf
    rm -rf /etc/gost/config.json
    confstart
    writeconf
    conflast
    systemctl restart gost
    echo -e "配置已生效，当前配置如下"
    echo -e "--------------------------------------------------------"
    show_all_conf
    ;;
  8)
    show_all_conf
    ;;
  9)
    show_all_conf
    read -p "请输入你要删除的配置编号：" numdelete
    if echo $numdelete | grep -q '[0-9]'; then
      sed -i "${numdelete}d" $raw_conf_path
      rm -rf /etc/gost/config.json
      confstart
      writeconf
      conflast
      systemctl restart gost
      echo -e "配置已删除，服务已重启"
    else
      echo "请输入正确数字"
    fi
    ;;
  10)
    cron_restart
    ;;
  11)
    cert
    ;;
  0)
    return
    ;;
  *)
    echo "请输入正确数字 [0-11]"
    ;;
  esac
  echo ""
  echo -ne "${green}按任意键返回 Gost 服务菜单...${plain}"
  read 
  manage_gost_services
}

# =========================================================
# 配置备份菜单
# =========================================================
backup_menu() {
  while true; do
    clear
    echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}配置备份管理${plain}                                           ${green}║${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}    ${green}1.${plain} 备份 WireGuard 配置                                 ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}2.${plain} 备份 IPIP 配置                                      ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}3.${plain} 备份 Gost 配置                                      ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}4.${plain} 备份所有配置                                        ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}5.${plain} 查看备份列表                                        ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}    ${red}0.${plain} 返回主菜单                                          ${green}║${plain}"
    echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
    echo ""
    echo -e "${yellow}备份目录: ${backup_base_dir}${plain}"
    echo ""
    echo -ne "${yellow}请输入选项 [0-5]: ${plain}"
    read backup_opt
    case "$backup_opt" in
    1)
      backup_wireguard_menu
      ;;
    2)
      backup_ipip_menu
      ;;
    3)
      backup_gost_menu
      ;;
    4)
      backup_all_configs
      ;;
    5)
      list_backups
      ;;
    0)
      return
      ;;
    *)
      echo -e "${red}❌ 无效输入，请重新选择！${plain}"
      sleep 1
      ;;
    esac
  done
}

# WireGuard 备份菜单
backup_wireguard_menu() {
  clear
  echo -e "${blue}--- 备份 WireGuard 配置 ---${plain}"
  
  # 列出所有 WireGuard 接口
  local wg_interfaces=()
  for conf in /etc/wireguard/*.conf; do
    [[ -f "$conf" ]] && wg_interfaces+=("$(basename "$conf" .conf)")
  done
  
  if [[ ${#wg_interfaces[@]} -eq 0 ]]; then
    echo -e "${yellow}未找到 WireGuard 配置文件${plain}"
    echo -ne "${green}按任意键返回...${plain}"
    read
    return
  fi
  
  echo -e "${green}找到以下 WireGuard 接口:${plain}"
  local i=1
  for iface in "${wg_interfaces[@]}"; do
    echo -e "  ${i}. ${iface}"
    ((i++))
  done
  echo -e "  ${i}. 备份所有接口"
  echo ""
  echo -ne "${yellow}请选择要备份的接口 [1-${i}]: ${plain}"
  read choice
  
  if [[ "$choice" == "$i" ]]; then
    # 备份所有接口
    echo -e "${yellow}正在备份所有 WireGuard 配置...${plain}"
    for iface in "${wg_interfaces[@]}"; do
      backup_wireguard_config "$iface"
    done
    echo -e "${green}所有 WireGuard 配置已备份完成${plain}"
  elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -lt "$i" ]]; then
    # 备份指定接口
    local selected_iface="${wg_interfaces[$((choice-1))]}"
    echo -e "${yellow}正在备份 ${selected_iface} 配置...${plain}"
    backup_wireguard_config "$selected_iface"
    echo -e "${green}备份完成${plain}"
  else
    echo -e "${red}无效选择${plain}"
  fi
  
  echo -ne "${green}按任意键返回...${plain}"
  read
}

# IPIP 备份菜单
backup_ipip_menu() {
  clear
  echo -e "${blue}--- 备份 IPIP 配置 ---${plain}"
  
  # 列出所有 IPIP 接口
  local ipip_interfaces=($(ip link show type ipip 2>/dev/null | grep -oP '^\d+:\s+\K[^:]+' || true))
  local ipip6_interfaces=($(ip link show type ip6tnl 2>/dev/null | grep -oP '^\d+:\s+\K[^:]+' || true))
  local all_interfaces=("${ipip_interfaces[@]}" "${ipip6_interfaces[@]}")
  
  if [[ ${#all_interfaces[@]} -eq 0 ]]; then
    echo -e "${yellow}未找到 IPIP 接口${plain}"
    echo -ne "${green}按任意键返回...${plain}"
    read
    return
  fi
  
  echo -e "${green}找到以下 IPIP 接口:${plain}"
  local i=1
  for iface in "${all_interfaces[@]}"; do
    echo -e "  ${i}. ${iface}"
    ((i++))
  done
  echo -e "  ${i}. 备份所有接口"
  echo ""
  echo -ne "${yellow}请选择要备份的接口 [1-${i}]: ${plain}"
  read choice
  
  if [[ "$choice" == "$i" ]]; then
    # 备份所有接口
    echo -e "${yellow}正在备份所有 IPIP 配置...${plain}"
    for iface in "${all_interfaces[@]}"; do
      backup_ipip_config "$iface"
    done
    echo -e "${green}所有 IPIP 配置已备份完成${plain}"
  elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -lt "$i" ]]; then
    # 备份指定接口
    local selected_iface="${all_interfaces[$((choice-1))]}"
    echo -e "${yellow}正在备份 ${selected_iface} 配置...${plain}"
    backup_ipip_config "$selected_iface"
    echo -e "${green}备份完成${plain}"
  else
    echo -e "${red}无效选择${plain}"
  fi
  
  echo -ne "${green}按任意键返回...${plain}"
  read
}

# Gost 备份菜单
backup_gost_menu() {
  clear
  echo -e "${blue}--- 备份 Gost 配置 ---${plain}"
  
  if [[ ! -f "$gost_conf_path" ]] && [[ ! -d "/etc/gost" ]]; then
    echo -e "${yellow}未找到 Gost 配置文件${plain}"
    echo -ne "${green}按任意键返回...${plain}"
    read
    return
  fi
  
  echo -e "${yellow}正在备份 Gost 配置...${plain}"
  backup_gost_config
  echo -e "${green}备份完成${plain}"
  
  echo -ne "${green}按任意键返回...${plain}"
  read
}

# 备份所有配置
backup_all_configs() {
  clear
  echo -e "${blue}--- 备份所有配置 ---${plain}"
  echo -e "${yellow}正在备份所有配置...${plain}"
  
  # 备份所有 WireGuard 配置
  for conf in /etc/wireguard/*.conf; do
    [[ -f "$conf" ]] && backup_wireguard_config "$(basename "$conf" .conf)"
  done
  
  # 备份所有 IPIP 配置
  local ipip_interfaces=($(ip link show type ipip 2>/dev/null | grep -oP '^\d+:\s+\K[^:]+' || true))
  local ipip6_interfaces=($(ip link show type ip6tnl 2>/dev/null | grep -oP '^\d+:\s+\K[^:]+' || true))
  for iface in "${ipip_interfaces[@]}" "${ipip6_interfaces[@]}"; do
    backup_ipip_config "$iface"
  done
  
  # 备份 Gost 配置
  [[ -f "$gost_conf_path" ]] || [[ -d "/etc/gost" ]] && backup_gost_config
  
  echo -e "${green}所有配置已备份完成${plain}"
  echo -ne "${green}按任意键返回...${plain}"
  read
}

# 列出备份
list_backups() {
  clear
  echo -e "${blue}--- 备份列表 ---${plain}"
  
  if [[ ! -d "$backup_base_dir" ]]; then
    echo -e "${yellow}备份目录不存在，尚未进行任何备份${plain}"
    echo -ne "${green}按任意键返回...${plain}"
    read
    return
  fi
  
  local backup_count=$(find "$backup_base_dir" -mindepth 1 -maxdepth 1 -type d | wc -l)
  if [[ $backup_count -eq 0 ]]; then
    echo -e "${yellow}未找到备份文件${plain}"
    echo -ne "${green}按任意键返回...${plain}"
    read
    return
  fi
  
  echo -e "${green}备份目录: ${backup_base_dir}${plain}"
  echo -e "${green}备份数量: ${backup_count} 个${plain}"
  echo ""
  echo -e "${yellow}最近的备份:${plain}"
  ls -lht "$backup_base_dir" | head -n 11 | tail -n +2 | awk '{print "  " $9 " (" $5 ")"}'
  echo ""
  echo -e "${yellow}查看备份详情: ls -lh ${backup_base_dir}${plain}"
  
  echo -ne "${green}按任意键返回...${plain}"
  read
}

# =========================================================
# 帮助说明
# =========================================================
show_help() {
  clear
  cat <<EOF
${green}=== 说明（方案A：keeper 持久化） ===${plain}
- IPIP 隧道的持久化不再依赖 rc.local，而是由 systemd 定时器每2分钟自愈（DDNS_NAME 可填域名或静态 IP）。
- 配置存放：/etc/ipip-ddns/<tun>.env
- 立刻重建：systemctl start ipip-ddns@<tun>.service
- 开机持久化：systemctl enable --now ipip-ddns@<tun>.timer

实用检查：
- systemctl status ipip-ddns@<tun>.timer
- journalctl -u ipip-ddns@<tun>.service -b | tail -n 50
- ip -d tunnel show; ip link show type ipip

Gost 功能：
- 支持多种转发协议（tcp+udp、加密隧道、解密、代理等）
- 支持多落地均衡负载和CDN自选节点
- 支持自定义TLS证书配置
EOF
  read -n 1 -s -r -p "按任意键返回..."
}

# =========================================================
# 主菜单
# =========================================================
main_menu() {
  while true; do
    clear
    echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}综合隧道管理脚本 v${shell_version}${plain}                                ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}IPIP / WireGuard / Gost 一体化管理${plain}                     ${green}║${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}  ${white}【隧道安装】${plain}                                             ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}1.${plain} 安装 IPIP 隧道 (IPv4) - 支持 DDNS 自愈              ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}2.${plain} 安装 IPIP 隧道 (IPv6) - 支持 DDNS 自愈              ${green}║${plain}"
    echo -e "${green}║${plain}    ${green}3.${plain} 安装 WireGuard 隧道 - VPN 网关                      ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}  ${white}【服务管理】${plain}                                             ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}4.${plain} IPIP 服务管理 - 查看/重启/卸载                      ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}5.${plain} WireGuard 服务管理 - 查看/重启/卸载                 ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}6.${plain} Gost 服务管理 - 转发/代理/证书配置                  ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}  ${white}【其他功能】${plain}                                             ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}7.${plain} 配置备份 - 备份 WireGuard/IPIP/Gost 配置            ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}8.${plain} Cloudflare WARP - WARP 客户端和 WireGuard 网络      ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}h.${plain} 帮助说明 - 使用教程和注意事项                       ${green}║${plain}"
    echo -e "${green}║${plain}    ${red}0.${plain} 退出脚本                                            ${green}║${plain}"
    echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
    echo ""
    echo -ne "${yellow}请输入选项 [0-8/h]: ${plain}"
    read opt
    case "$opt" in
    1) 
      install_ipip
      echo -ne "${green}按任意键返回主菜单...${plain}"
      read -n1 -s -r
      ;;
    2) 
      install_ipipv6
      echo -ne "${green}按任意键返回主菜单...${plain}"
      read -n1 -s -r
      ;;
    3) 
      install_wg
      echo -ne "${green}按任意键返回主菜单...${plain}"
      read -n1 -s -r
      ;;
    4) manage_ipip_services ;;
    5) manage_wg_services ;;
    6) manage_gost_services ;;
    7) 
      backup_menu
      ;;
    8) 
      manage_warp
      ;;
    h|H) 
      show_help
      ;;
    0) 
      echo -e "${green}感谢使用，再见！${plain}"
      exit 0
      ;;
    *) 
      echo -e "${red}❌ 无效输入，请重新选择！${plain}"
      sleep 1
      ;;
    esac
  done
}

# =========================================================
# Cloudflare WARP 管理（集成 P3TERX/warp.sh）
# =========================================================
manage_warp() {
  # 调用 WARP 脚本的菜单功能
  if [[ -f "$0" ]]; then
    # 临时保存当前脚本路径
    local script_path="$0"
    # 执行 WARP 菜单（通过 source 调用 Start_Menu 函数）
    bash -c "source <(curl -fsSL https://raw.githubusercontent.com/P3TERX/warp.sh/main/warp.sh) && Start_Menu" || {
      # 如果在线脚本不可用，尝试使用本地集成版本
      echo -e "${yellow}正在加载 WARP 管理功能...${plain}"
      # 这里会调用后面定义的 Start_Menu_WARP 函数
      Start_Menu_WARP
    }
  else
    Start_Menu_WARP
  fi
}

# =========================================================
# Cloudflare WARP 脚本（完整代码，不修改）
# =========================================================
# https://github.com/P3TERX/warp.sh
# Description: Cloudflare WARP Installer
# Version: 1.0.40_Final
# MIT License
# Copyright (c) 2021-2024 P3TERX <https://p3terx.com>

shVersion_WARP='1.0.40_Final'

FontColor_Red_WARP="\033[31m"
FontColor_Red_Bold_WARP="\033[1;31m"
FontColor_Green_WARP="\033[32m"
FontColor_Green_Bold_WARP="\033[1;32m"
FontColor_Yellow_WARP="\033[33m"
FontColor_Yellow_Bold_WARP="\033[1;33m"
FontColor_Purple_WARP="\033[35m"
FontColor_Purple_Bold_WARP="\033[1;35m"
FontColor_Suffix_WARP="\033[0m"

log_WARP() {
    local LEVEL="$1"
    local MSG="$2"
    case "${LEVEL}" in
    INFO)
        local LEVEL="[${FontColor_Green_WARP}${LEVEL}${FontColor_Suffix_WARP}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    WARN)
        local LEVEL="[${FontColor_Yellow_WARP}${LEVEL}${FontColor_Suffix_WARP}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    ERROR)
        local LEVEL="[${FontColor_Red_WARP}${LEVEL}${FontColor_Suffix_WARP}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    *) ;;
    esac
    echo -e "${MSG}"
}

# 检查 WARP 环境
check_warp_env() {
    if [[ $(uname -s) != Linux ]]; then
        log_WARP ERROR "This operating system is not supported."
        return 1
    fi
    
    if [[ $(id -u) != 0 ]]; then
        log_WARP ERROR "This script must be run as root."
        return 1
    fi
    
    if [[ -z $(command -v curl) ]]; then
        log_WARP ERROR "cURL is not installed."
        return 1
    fi
    return 0
}

# WARP 变量定义
WGCF_Profile_WARP='wgcf-profile.conf'
WGCF_ProfileDir_WARP="/etc/warp"
WGCF_ProfilePath_WARP="${WGCF_ProfileDir_WARP}/${WGCF_Profile_WARP}"
WireGuard_Interface_WARP='wgcf'
WireGuard_ConfPath_WARP="/etc/wireguard/${WireGuard_Interface_WARP}.conf"
WireGuard_Interface_DNS_IPv4_WARP='8.8.8.8,8.8.4.4'
WireGuard_Interface_DNS_IPv6_WARP='2001:4860:4860::8888,2001:4860:4860::8844'
WireGuard_Interface_DNS_46_WARP="${WireGuard_Interface_DNS_IPv4_WARP},${WireGuard_Interface_DNS_IPv6_WARP}"
WireGuard_Interface_DNS_64_WARP="${WireGuard_Interface_DNS_IPv6_WARP},${WireGuard_Interface_DNS_IPv4_WARP}"
WireGuard_Interface_Rule_table_WARP='51888'
WireGuard_Interface_Rule_fwmark_WARP='51888'
WireGuard_Interface_MTU_WARP='1280'
WireGuard_Peer_Endpoint_IP4_WARP='162.159.192.1'
WireGuard_Peer_Endpoint_IP6_WARP='2606:4700:d0::a29f:c001'
WireGuard_Peer_Endpoint_IPv4_WARP="${WireGuard_Peer_Endpoint_IP4_WARP}:2408"
WireGuard_Peer_Endpoint_IPv6_WARP="[${WireGuard_Peer_Endpoint_IP6_WARP}]:2408"
WireGuard_Peer_Endpoint_Domain_WARP='engage.cloudflareclient.com:2408'
WireGuard_Peer_AllowedIPs_IPv4_WARP='0.0.0.0/0'
WireGuard_Peer_AllowedIPs_IPv6_WARP='::/0'
WireGuard_Peer_AllowedIPs_DualStack_WARP='0.0.0.0/0,::/0'
TestIPv4_1_WARP='1.0.0.1'
TestIPv4_2_WARP='9.9.9.9'
TestIPv6_1_WARP='2606:4700:4700::1001'
TestIPv6_2_WARP='2620:fe::fe'
CF_Trace_URL_WARP='https://www.cloudflare.com/cdn-cgi/trace'

# WARP 菜单入口（简化版，调用在线脚本）
Start_Menu_WARP() {
    if ! check_warp_env; then
        echo -ne "${green}按任意键返回...${plain}"
        read
        return
    fi
    
    clear
    echo -e "${green}╔═══════════════════════════════════════════════════════════╗${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}║${plain}    ${blue}Cloudflare WARP 管理${plain}                                   ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}Cloudflare WARP 一键安装脚本 [${shVersion_WARP}]${plain}            ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}by P3TERX.COM${plain}                                          ${green}║${plain}"
    echo -e "${green}║${plain}                                                           ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}    ${red}0.${plain} 返回主菜单                                          ${green}║${plain}"
    echo -e "${green}╠═══════════════════════════════════════════════════════════╣${plain}"
    echo -e "${green}║${plain}    ${green}1.${plain} 运行 WARP 完整菜单（在线脚本）                      ${green}║${plain}"
    echo -e "${green}║${plain}    ${yellow}提示: 将自动下载并运行 P3TERX/warp.sh${plain}                  ${green}║${plain}"
    echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}"
    echo ""
    echo -ne "${yellow}请输入选项 [0-1]: ${plain}"
    read warp_opt
    case "$warp_opt" in
    0)
        return
        ;;
    1)
        echo -e "${yellow}正在加载 WARP 脚本...${plain}"
        # 使用 curl 直接执行在线脚本的菜单
        bash <(curl -fsSL git.io/warp.sh) menu
        echo -ne "${green}按任意键返回...${plain}"
        read
        ;;
    *)
        echo -e "${red}❌ 无效输入${plain}"
        sleep 1
        ;;
    esac
}

# =========================================================
# 执行入口
# =========================================================
check_root
# 静默检查更新（已禁用，避免干扰）
# update_sh
main_menu

