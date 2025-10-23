#!/bin/bash
# =========================================================
# 综合隧道管理脚本：IPIP / WireGuard / Gost 一体化管理
# 最终优化生产级版本
# =========================================================

# --- 全局颜色变量 ---
red='\033[0;31m'
green='\033[0;32m'
white='\033[37m' # 统一小写命名
blue='\033[36m'
yellow='\033[0;33m'
plain='\033[0m'

# --- Gost 脚本全局变量 ---
shell_version="1.1.2" # 版本升级，体现优化
ct_new_ver="2.11.2"
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"
Info="${green}[信息]${plain}"
Error="${red}[错误]${plain}"

# --- IPIP/WireGuard 全局变量 ---
DATE=$(date +%Y%m%d)

# =========================================================
# 权限检查
# =========================================================
check_root() {
[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${green}sudo su${plain} 命令获取临时ROOT权限。" && exit 1
}

# =========================================================
# 确保 rc.local 存在（抽离重复代码）
# =========================================================
ensure_rc_local() {
if [[ ! -f /etc/rc.local ]]; then
cat > /etc/rc.local <<EOF
#!/bin/sh -e
exit 0
EOF
chmod +x /etc/rc.local
echo -e "${blue}/etc/rc.local 已创建并赋予执行权限。${plain}"
fi
}

# =========================================================
# 系统检测（兼容现代发行版）
# =========================================================
function check_sys() {
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
}

# =========================================================
# --- IPIP 服务相关功能函数 ---
# =========================================================

manage_ipip_services() {
clear
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${green} IPIP 服务管理 ${plain}"
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${red}0.${plain} 返回主菜单"
echo -e "${green}1.${plain} 一键查看所有 IPIP 接口"
echo -e "${green}2.${plain} 一键重启 IPIP 接口"
echo -e "${green}3.${plain} 一键卸载 IPIP 接口"
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${yellow}请选择你要使用的功能${plain}"
read -p "请输入数字 :" ipip_num

case "$ipip_num" in
0)
return
;;
1)
view_ipip_interfaces
;;
2)
reboot_ipip_interface
;;
3)
uninstall_ipip_interface
;;
*)
echo -e "${red}出现错误:请输入正确数字 ${plain}"
sleep 2s
;;
esac
read -p "按任意键返回 IPIP 服务菜单..."
manage_ipip_services
}

view_ipip_interfaces() {
clear
echo -e "${blue}--- 已部署的 IPIP 接口 ---${plain}"
local ipip_v4_links=$(ip -o link show type ipip | awk '{print $2}' | sed 's/://g' | sed 's/@NONE//g')
local ipip_v6_links=$(ip -o link show type ip6tnl | awk '{print $2}' | sed 's/://g' | sed 's/@NONE//g')

if [[ -z "$ipip_v4_links" && -z "$ipip_v6_links" ]]; then
echo -e "${yellow}未检测到任何正在运行的 IPIP (IPv4/IPv6) 隧道接口。${plain}"
else
echo -e "${green}--- IPv4 IPIP 隧道 ---${plain}"
if [[ -n "$ipip_v4_links" ]]; then
echo "$ipip_v4_links" | while read -r tun_name; do
local tun_details=$(ip tunnel show "$tun_name" 2>/dev/null)
local local_ip=$(echo "$tun_details" | grep -Eo 'local ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' || echo "N/A")
local remote_ip=$(echo "$tun_details" | grep -Eo 'remote ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' || echo "N/A")
local tun_ip=$(ip addr show dev "$tun_name" | grep "inet " | awk '{print $2}' | cut -d'/' -f1 || echo "N/A")
echo -e " ${green}接口名称:${plain} $tun_name"
echo -e " ${green}本地公网IP:${plain} $local_ip"
echo -e " ${green}对端公网IP:${plain} $remote_ip"
echo -e " ${green}隧道内部IP:${plain} $tun_ip"
echo "--------------------"
done
else
echo -e "${yellow}无 IPv4 IPIP 隧道。${plain}"
fi

echo -e "${green}--- IPv6 IPIP 隧道 ---${plain}"
if [[ -n "$ipip_v6_links" ]]; then
echo "$ipip_v6_links" | while read -r tun_name; do
local tun_details=$(ip -6 tunnel show "$tun_name" 2>/dev/null)
local local_ip6=$(echo "$tun_details" | grep -Eo 'local ([0-9a-fA-F:]+)' | awk '{print $2}' || echo "N/A")
local remote_ip6=$(echo "$tun_details" | grep -Eo 'remote ([0-9a-fA-F:]+)' | awk '{print $2}' || echo "N/A")
local tun_ip6=$(ip addr show dev "$tun_name" | grep "inet6 " | awk '{print $2}' | cut -d'/' -f1 || echo "N/A")
echo -e " ${green}接口名称:${plain} $tun_name"
echo -e " ${green}本地公网IPv6:${plain} $local_ip6"
echo -e " ${green}对端公网IPv6:${plain} $remote_ip6"
echo -e " ${green}隧道内部IPv6:${plain} $tun_ip6"
echo "--------------------"
done
else
echo -e "${yellow}无 IPv6 IPIP 隧道。${plain}"
fi
fi
}

select_ipip_interface() {
local tun_list=()
local ipip_v4_names=()
while IFS= read -r name; do
ipip_v4_names+=("$name")
done < <(ip -o link show type ipip | awk '{print $2}' | sed 's/://g' | sed 's/@NONE//g')

local ipip_v6_names=()
while IFS= read -r name; do
ipip_v6_names+=("$name")
done < <(ip -o link show type ip6tnl | awk '{print $2}' | sed 's/://g' | sed 's/@NONE//g')

if [[ ${#ipip_v4_names[@]} -gt 0 ]]; then
for name in "${ipip_v4_names[@]}"; do
tun_list+=("$name (IPv4)")
done
fi
if [[ ${#ipip_v6_names[@]} -gt 0 ]]; then
for name in "${ipip_v6_names[@]}"; do
tun_list+=("$name (IPv6)")
done
fi

if [[ ${#tun_list[@]} -eq 0 ]]; then
echo -e "${red}未检测到任何 IPIP 隧道接口。${plain}" >&2
return 1
fi

PS3="请选择要操作的 IPIP 隧道接口 (输入数字): "
local selected_choice
local chosen_raw_name=""
select selected_choice in "${tun_list[@]}"; do
if [[ -n "$selected_choice" ]]; then
chosen_raw_name="$(echo "$selected_choice" | awk '{print $1}')"
echo "$chosen_raw_name"
return 0
else
echo -e "${red}无效的选择，请重新输入。${plain}" >&2
fi
done
return 1
}

reboot_ipip_interface() {
clear
echo -e "${blue}--- 重启 IPIP 接口 ---${plain}"
local chosen_tun_name=$(select_ipip_interface)
local select_status=$?

if [[ $select_status -ne 0 || -z "$chosen_tun_name" ]]; then
echo -e "${red}接口选择失败，无法执行重启操作。${plain}"
return
fi

echo -e "${yellow}正在重启接口 ${chosen_tun_name}...${plain}"
ip link set "$chosen_tun_name" down &>/dev/null
ip tunnel del "$chosen_tun_name" &>/dev/null
ip -6 tunnel del "$chosen_tun_name" &>/dev/null

local escaped_tun_name=$(echo "$chosen_tun_name" | sed 's/[][\/.^$*+?()|]/\\&/g')
local rc_local_config_cmds=()
while IFS= read -r line; do
case "$line" in
ip\ tunnel\ add*"$escaped_tun_name"* | \
ip\ link\ add\ name\ *"$escaped_tun_name"* | \
ip\ addr\ add*\ dev\ *"$escaped_tun_name"* | \
ip\ -6\ addr\ add*\ dev\ *"$escaped_tun_name"* | \
ip\ link\ set\ *"$escaped_tun_name"\ up | \
ip\ -6\ route\ add*\ dev\ *"$escaped_tun_name"* | \
dhclient\ -6\ *"$escaped_tun_name"*)
rc_local_config_cmds+=("$line")
;;
esac
done < /etc/rc.local

if [[ ${#rc_local_config_cmds[@]} -gt 0 ]]; then
echo -e "${blue}从 /etc/rc.local 重新执行配置命令...${plain}"
local success=true
for cmd in "${rc_local_config_cmds[@]}"; do
echo "执行: $cmd"
bash -c "$cmd" # 替代 eval，更安全
if [ $? -ne 0 ]; then
echo -e "${red}命令执行失败: $cmd${plain}"
success=false
fi
done

if $success; then
echo -e "${green}接口 ${chosen_tun_name} 重启成功。${plain}"
else
echo -e "${red}接口 ${chosen_tun_name} 重启失败，请手动检查 /etc/rc.local 配置和日志。${plain}"
fi
else
echo -e "${red}未在 /etc/rc.local 中找到接口 ${chosen_tun_name} 的配置。这可能导致重启后无法正确恢复。${plain}"
echo -e "${yellow}尝试直接启用该接口...${plain}"
ip link set "$chosen_tun_name" up &>/dev/null
if [ $? -eq 0 ]; then
echo -e "${green}接口 ${chosen_tun_name} 已启用。${plain}"
else
echo -e "${red}接口 ${chosen_tun_name} 启用失败。${plain}"
fi
fi
}

uninstall_ipip_interface() {
clear
echo -e "${blue}--- 卸载 IPIP 接口 ---${plain}"
local chosen_tun_name=$(select_ipip_interface)
local select_status=$?

if [[ $select_status -ne 0 || -z "$chosen_tun_name" ]]; then
echo -e "${red}接口选择失败，无法执行卸载操作。${plain}"
return
fi

read -p "警告: 卸载 ${chosen_tun_name} 会中断所有通过此隧道的网络连接。确定要继续吗？(Y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
echo -e "${yellow}操作已取消。${plain}"
return
fi

echo -e "${yellow}正在卸载接口 ${chosen_tun_name}...${plain}"
local escaped_tun_name=$(echo "$chosen_tun_name" | sed 's/[][\/.^$*+?()|]/\\&/g')
sed -i "/ip tunnel add ${escaped_tun_name}/d" /etc/rc.local
sed -i "/ip link add name ${escaped_tun_name}/d" /etc/rc.local
sed -i "/ip addr add .* dev ${escaped_tun_name}/d" /etc/rc.local
sed -i "/ip link set ${escaped_tun_name} up/d" /etc/rc.local
sed -i "/ip -6 route add .* dev ${escaped_tun_name}/d" /etc/rc.local
sed -i "/dhclient -6 ${escaped_tun_name}/d" /etc/rc.local
if ! grep -q "^exit 0$" /etc/rc.local; then
echo "exit 0" >> /etc/rc.local
fi
systemctl daemon-reload &>/dev/null
systemctl restart rc-local &>/dev/null

ip link set "$chosen_tun_name" down &>/dev/null
ip tunnel del "$chosen_tun_name" &>/dev/null
ip -6 tunnel del "$chosen_tun_name" &>/dev/null

local cron_script_pattern="/root/change-tunnel-ip_${chosen_tun_name}_*.sh"
if ls "$cron_script_pattern" 1>/dev/null 2>&1; then
echo -e "${blue}正在移除动态 IP 更新脚本和 Cron 定时任务...${plain}"
local script_to_remove_path=$(ls "$cron_script_pattern" | head -n 1)
local script_basename=$(basename "$script_to_remove_path")
crontab -l 2>/dev/null | grep -v "$script_basename" | crontab -
rm -f "$script_to_remove_path"
rm -f "/root/.tunnel-ip-${chosen_tun_name}.txt"
fi

echo -e "${yellow}请手动检查 iptables 中是否有与此隧道相关的 POSTROUTING 或转发规则并手动清理。${plain}"
echo -e "${yellow}例如: 'iptables -t nat -L --line-numbers' 或 'iptables -L --line-numbers'${plain}"
echo -e "${yellow}然后用 'iptables -t nat -D POSTROUTING [行号]' 或 'iptables -D FORWARD [行号]' 来删除。${plain}"

echo -e "${green}接口 ${chosen_tun_name} 已成功卸载。${plain}"
}

# --- 安装IPIP IPv4 函数 ---
install_ipip(){
local ddnsname tunname vip_cidr vip remotevip netcardname localip remoteip
echo -e "${blue}--- 正在部署 IPIPv4 隧道 ---${plain}"
if ! lsmod | grep -q ipip; then
modprobe ipip
echo -e "${green}已加载 ipip 模块。${plain}"
fi
if ! command -v dig &> /dev/null; then
echo -e "${blue}正在安装 dnsutils (dig)...${plain}"
apt-get install dnsutils -y >/dev/null 2>&1 || yum install bind-utils -y >/dev/null 2>&1
fi
if ! command -v iptables &> /dev/null; then
echo -e "${blue}正在安装 iptables...${plain}"
apt install iptables -y >/dev/null 2>&1 || yum install iptables -y >/dev/null 2>&1
fi

ensure_rc_local

echo -ne "${yellow}请输入对端设备的ddns域名或者IP：${plain}"
read ddnsname
echo -ne "${yellow}请输入要创建的tun网卡名称(例如 tun_ipip, tun_ipip_bc)：${plain}"
read tunname
echo -ne "${yellow}请输入本机tun网口的IPIP内部V-IP (例如 192.168.100.2/30)：${plain}"
read vip_cidr

if ! [[ "$vip_cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
echo -e "${red}错误: 请输入有效的 IPv4 CIDR，如 192.168.100.2/30${plain}"
exit 1
fi

vip=$(echo "$vip_cidr" | cut -d'/' -f1)
echo -ne "${yellow}请输入对端tun网口的IPIP内部V-IP (例如 192.168.100.1)：${plain}"
read remotevip

netcardname=$(ls /sys/class/net | awk '/^e/{print; exit}')
if [[ -z "$netcardname" ]]; then
echo -e "${red}错误: 无法自动检测到网络接口名称，请手动输入。${plain}"
read -p "${yellow}请输入您的主网络接口名称 (例如 eth0, ens3, enp0s3): ${plain}" netcardname
if [[ -z "$netcardname" ]]; then
echo -e "${red}错误: 未输入网络接口名称，程序退出。${plain}"
exit 1
fi
fi

localip=$(ip a | grep "inet " | grep "global" | grep "$netcardname" | awk '{print $2}' | cut -d'/' -f1)
if [[ -z "$localip" ]]; then
echo -e "${red}错误: 无法获取本机公网 IP，请检查网络配置或手动指定。${plain}"
read -p "${yellow}请输入本机的公网 IP : ${plain}" localip
if [[ -z "$localip" ]]; then
echo -e "${red}错误: 未输入本机公网 IP，程序退出。${plain}"
exit 1
fi
fi

remoteip=""
if ! echo "$ddnsname" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
dig_output=$(dig +short A "$ddnsname" 2>/dev/null)
if [[ -n "$dig_output" && "$dig_output" != *"error"* ]]; then
remoteip=$(echo "$dig_output" | head -n 1)
echo -e "${green}通过 DDNS 解析对端 IP 为: ${remoteip}${plain}"
else
ping_output=$(ping -4 -c 1 "$ddnsname" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
if [[ -n "$ping_output" ]]; then
remoteip=$ping_output
echo -e "${green}通过 Ping 解析对端 IP 为: ${remoteip}${plain}"
else
echo -e "${red}错误: 无法解析或获取对端设备的IP。请确认输入是有效的IP地址或域名。${plain}"
exit 1
fi
fi
else
remoteip="$ddnsname"
echo -e "${green}对端 IP 为: ${remoteip} (直接输入)${plain}"
fi

echo -e "${blue}正在更新 /etc/rc.local 文件...${plain}"
sed -i '/^exit 0$/d' /etc/rc.local
echo "ip tunnel add $tunname mode ipip remote ${remoteip} local ${localip} ttl 64" >> /etc/rc.local
echo "ip addr add ${vip_cidr} dev $tunname" >> /etc/rc.local
echo "ip link set $tunname up" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local

if ! echo "$ddnsname" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
echo -e "${blue}创建动态 IP 更新脚本 /root/change-tunnel-ip_${tunname}_${DATE}.sh ...${plain}"
cat >"/root/change-tunnel-ip_${tunname}_${DATE}.sh" <<EOF
#!/bin/bash
LAST_KNOWN_REMOTE_IP_FILE="/root/.tunnel-ip-${tunname}.txt"
TUN_NAME="${tunname}"
DDNS_NAME="${ddnsname}"
LOCAL_IP="${localip}"
VIP_CIDR="${vip_cidr}"

get_remote_ip() {
dig +short A "\$DDNS_NAME" 2>/dev/null | head -n 1 || \\
ping -4 -c 1 "\$DDNS_NAME" 2>/dev/null | grep -Eo '([0-9]{1,3}\\.){3}[0-9]{1,3}' | head -n 1
}

while true; do
REMOTE_IP_DYN=\$(get_remote_ip)
if [[ -z "\$REMOTE_IP_DYN" ]]; then
echo -e "$(date): 无法获取对端 (\$DDNS_NAME) 的动态 IP。等待重试..." >&2
sleep 10
continue
fi

OLD_REMOTE_IP=\$(cat "\$LAST_KNOWN_REMOTE_IP_FILE" 2>/dev/null)

if [[ "\$OLD_REMOTE_IP" != "\$REMOTE_IP_DYN" ]]; then
echo -e "$(date): 对端IP发生变化，从 \$OLD_REMOTE_IP 变为 \$REMOTE_IP_DYN ，正在更新隧道..."

ip tunnel del "\$TUN_NAME" &>/dev/null
sed -i "s/ip tunnel add \$TUN_NAME mode ipip.*/ip tunnel add \$TUN_NAME mode ipip remote \${REMOTE_IP_DYN} local \${LOCAL_IP} ttl 64/" /etc/rc.local
systemctl restart rc-local &>/dev/null

for _L_wg_conf in /etc/wireguard/*.conf; do
if [[ -f "\$_L_wg_conf" ]] && (grep -q "Endpoint = \${OLD_REMOTE_IP}:" "\$_L_wg_conf" || grep -q "Endpoint = \\\\\[\${OLD_REMOTE_IP}\\\\]:" "\$_L_wg_conf"); then
_L_WG_IFACE=\$(basename "\$_L_wg_conf" .conf)
echo "重启 WireGuard 接口 \$_L_WG_IFACE (因 IPIP 隧道外部 IP 变化)..."
wg-quick down "\$_L_WG_IFACE" &>/dev/null
wg-quick up "\$_L_WG_IFACE" &>/dev/null
fi
done

echo "\$REMOTE_IP_DYN" > "\$LAST_KNOWN_REMOTE_IP_FILE"
echo "隧道已更新为新IP。"
else
echo -e "$(date): 对端IP未变化。" >&2
fi
sleep 120
done
EOF
chmod 700 "/root/change-tunnel-ip_${tunname}_${DATE}.sh" # 安全权限
echo -e "${blue}开始添加定时任务以监控对端IP变化...${plain}"
bashsrc=$(which bash)
crontab -l 2>/dev/null | grep -v "/root/change-tunnel-ip_${tunname}_${DATE}.sh" > /tmp/crontab_tmp.$$
echo "*/2 * * * * ${bashsrc} /root/change-tunnel-ip_${tunname}_${DATE}.sh > /dev/null 2>&1" >> /tmp/crontab_tmp.$$
crontab /tmp/crontab_tmp.$$
rm -f /tmp/crontab_tmp.$$
echo -e "${green}定时任务设置成功。${plain}"
echo "${remoteip}" > "/root/.tunnel-ip-${tunname}.txt"
fi

ip tunnel add "$tunname" mode ipip remote "${remoteip}" local "${localip}" ttl 64 &>/dev/null
ip addr add "${vip_cidr}" dev "$tunname"
ip link set "$tunname" up
echo -e "${green}IPIP 隧道 ${tunname} 已创建并启用。${plain}"
echo -e "${green}本机 IPIP 隧道 IP: ${vip_cidr}${plain}"
echo -e "${green}对端 IPIP 隧道 IP: ${remotevip}${plain}"

ip route add "${remotevip}/32" dev "$tunname" scope link src "${vip}" &>/dev/null

if ! iptables -t nat -C POSTROUTING -s "${remotevip}" -j MASQUERADE 2>/dev/null; then
iptables -t nat -A POSTROUTING -s "${remotevip}" -j MASQUERADE
echo -e "${green}已添加 iptables MASQUERADE 规则。${plain}"
fi

if ! sysctl net.ipv4.ip_forward | grep -q " = 1"; then
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf &>/dev/null
echo -e "${green}已启用 IPv4 转发。${plain}"
fi

cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
systemctl enable rc-local &>/dev/null
systemctl start rc-local &>/dev/null
echo -e "${green}rc.local 服务已启用并启动。${plain}"

echo -e "${green}-------------------------------------------------------${plain}"
echo -e "${green}IPIP 隧道配置完成。请测试 ping ${remotevip}${plain}"
echo -e "${green}-------------------------------------------------------${plain}"
}

# --- 安装IPIP IPv6 函数 ---
install_ipipv6(){
local ddnsname tunname vip_cidr vip remotevip netcardname localip6 remoteip routerule addtxt addtxt1
echo -e "${blue}--- 正在部署 IPIPv6 隧道 ---${plain}"
if ! lsmod | grep -q ip6_tunnel; then
modprobe ip6_tunnel
echo -e "${green}已加载 ip6_tunnel 模块。${plain}"
fi
if ! command -v iptables &> /dev/null; then
echo -e "${blue}正在安装 iptables...${plain}"
apt install iptables -y >/dev/null 2>&1 || yum install iptables -y >/dev/null 2>&1
fi

ensure_rc_local

echo -ne "${yellow}请输入对端设备的ddns域名或者IP (IPv6)：${plain}"
read ddnsname
echo -ne "${yellow}请输入要创建的tun网卡名称(例如 tun_ipip6_bc)：${plain}"
read tunname
echo -ne "${yellow}请输入本机tun网口的V-IP (例如 fdef:1::1/64)：${plain}"
read vip_cidr

if ! [[ "$vip_cidr" =~ ^([0-9a-fA-F:]+(/[0-9]{1,3})?)$ ]]; then
echo -e "${red}错误: 请输入有效的 IPv6 CIDR，如 fdef:1::1/64${plain}"
exit 1
fi

vip=$(echo "$vip_cidr" | cut -d'/' -f1)
echo -ne "${yellow}请输入对端的V-IP (例如 fdef:1::2)：${plain}"
read remotevip

netcardname=$(ls /sys/class/net | awk '/^e/{print; exit}')
if [[ -z "$netcardname" ]]; then
echo -e "${red}错误: 无法自动检测到网络接口名称，请手动输入。${plain}"
read -p "${yellow}请输入您的主网络接口名称 (例如 eth0, ens3, enp0s3): ${plain}" netcardname
if [[ -z "$netcardname" ]]; then
echo -e "${red}错误: 未输入网络接口名称，程序退出。${plain}"
exit 1
fi
fi

routerule=$(ip -6 route list | grep default | head -n1)
localip6=$(ip a | grep inet6 | grep 'scope global' | grep "$netcardname" | awk '{print $2}' | cut -d'/' -f1)
if [[ -z "$localip6" ]]; then
echo -e "${red}错误: 无法获取本机 IPv6 公网 IP，请检查网络配置或手动指定。${plain}"
read -p "${yellow}请输入本机的 IPv6 公网 IP : ${plain}" localip6
if [[ -z "$localip6" ]]; then
echo -e "${red}错误: 未输入本机 IPv6 公网 IP，程序退出。${plain}"
exit 1
fi
fi

remoteip=""
if ! echo "$ddnsname" | grep -Eq '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}$|:((:[0-9a-fA-F]{1,4}){1,6}|:)$'; then
dig_output=$(dig +short AAAA "$ddnsname" 2>/dev/null)
if [[ -n "$dig_output" && "$dig_output" != *"error"* ]]; then
remoteip=$(echo "$dig_output" | head -n 1)
echo -e "${green}通过 DDNS 解析对端 IPv6 为: ${remoteip}${plain}"
else
ping_output=$(ping6 -c 1 "$ddnsname" 2>/dev/null | grep -Eo '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:' | head -n 1)
if [[ -n "$ping_output" ]]; then
remoteip=$ping_output
echo -e "${green}通过 Ping 解析对端 IPv6 为: ${remoteip}${plain}"
else
echo -e "${red}错误: 无法解析或获取对端设备的IPv6。请确认输入是有效的IPv6地址或域名。${plain}"
exit 1
fi
fi
else
remoteip="$ddnsname"
echo -e "${green}对端 IPv6 为: ${remoteip} (直接输入)${plain}"
fi

if ! echo "$ddnsname" | grep -Eq '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}$|:((:[0-9a-fA-F]{1,4}){1,6}|:)$'; then
echo -e "${blue}创建动态 IP 更新脚本 /root/change-tunnel-ip_${tunname}_${DATE}.sh ...${plain}"
cat >"/root/change-tunnel-ip_${tunname}_${DATE}.sh" <<EOF
#!/bin/bash
LAST_KNOWN_REMOTE_IP_FILE="/root/.tunnel-ip-${tunname}.txt"
TUN_NAME="${tunname}"
DDNS_NAME="${ddnsname}"
LOCAL_IP6="${localip6}"
VIP_CIDR="${vip_cidr}"

get_remote_ip6() {
dig +short AAAA "\$DDNS_NAME" 2>/dev/null | head -n 1 || \\
ping6 -c 1 "\$DDNS_NAME" 2>/dev/null | grep -Eo '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:' | head -n 1
}

while true; do
REMOTE_IP_DYN=\$(get_remote_ip6)
if [[ -z "\$REMOTE_IP_DYN" ]]; then
echo -e "$(date): 无法获取对端 (\$DDNS_NAME) 的动态 IPv6。等待重试..." >&2
sleep 10
continue
fi
OLD_REMOTE_IP=\$(cat "\$LAST_KNOWN_REMOTE_IP_FILE" 2>/dev/null)
if [[ "\$OLD_REMOTE_IP" != "\$REMOTE_IP_DYN" ]]; then
echo -e "$(date): 对端IPv6发生变化，从 \$OLD_REMOTE_IP 变为 \$REMOTE_IP_DYN ，正在更新隧道..."
ip -6 tunnel del "\$TUN_NAME" &>/dev/null
sed -i "s/ip link add name \$TUN_NAME.*/ip link add name \$TUN_NAME type ip6tnl local \${LOCAL_IP6} remote \${REMOTE_IP_DYN} mode any/" /etc/rc.local
systemctl restart rc-local &>/dev/null

for _L_wg_conf in /etc/wireguard/*.conf; do
if [[ -f "\$_L_wg_conf" ]] && grep -q "Endpoint = \\\\\[\${OLD_REMOTE_IP}\\\\]:" "\$_L_wg_conf"; then
_L_WG_IFACE=\$(basename "\$_L_wg_conf" .conf)
echo "重启 WireGuard 接口 \$_L_WG_IFACE (因 IPIPv6 隧道外部 IP 变化)..."
wg-quick down "\$_L_WG_IFACE" &>/dev/null
wg-quick up "\$_L_WG_IFACE" &>/dev/null
fi
done

echo "\$REMOTE_IP_DYN" > "\$LAST_KNOWN_REMOTE_IP_FILE"
echo "隧道已更新为新IPv6。"
else
echo -e "$(date): 对端IPv6未变化。" >&2
fi
sleep 120
done
EOF
chmod 700 "/root/change-tunnel-ip_${tunname}_${DATE}.sh"
echo -e "${blue}开始添加定时任务以监控对端IPv6变化...${plain}"
bashsrc=$(which bash)
crontab -l 2>/dev/null | grep -v "/root/change-tunnel-ip_${tunname}_${DATE}.sh" > /tmp/crontab_tmp.$$
echo "*/2 * * * * ${bashsrc} /root/change-tunnel-ip_${tunname}_${DATE}.sh > /dev/null 2>&1" >> /tmp/crontab_tmp.$$
crontab /tmp/crontab_tmp.$$
rm -f /tmp/crontab_tmp.$$
echo -e "${green}定时任务设置成功。${plain}"
echo "${remoteip}" > "/root/.tunnel-ip-${tunname}.txt"
fi

read -p "${yellow}当前机器是甲骨文吗？[Y/N]:${plain}" yn
if [[ $yn == "Y" ]]||[[ $yn == "y" ]]; then
addtxt="dhclient -6 $netcardname"
addtxt1="sleep 20s"
fi

echo -e "${blue}正在更新 /etc/rc.local 文件...${plain}"
sed -i '/^exit 0$/d' /etc/rc.local
[[ -n "$addtxt1" ]] && echo "$addtxt1" >> /etc/rc.local
[[ -n "$addtxt" ]] && echo "$addtxt" >> /etc/rc.local
echo "ip link add name $tunname type ip6tnl local ${localip6} remote ${remoteip} mode any" >> /etc/rc.local
echo "ip -6 addr add ${vip_cidr} dev ${tunname}" >> /etc/rc.local
echo "ip link set $tunname up" >> /etc/rc.local
[[ -n "$routerule" ]] && echo "ip -6 route add $routerule" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local

ip link add name "$tunname" type ip6tnl local "${localip6}" remote "${remoteip}" mode any &>/dev/null
ip -6 addr add "${vip_cidr}" dev "$tunname"
ip link set "$tunname" up
[[ -n "$routerule" ]] && ip -6 route add "$routerule" &>/dev/null
echo -e "${green}IPIPv6 隧道 ${tunname} 已创建并启用。${plain}"
echo -e "${green}本机 IPIPv6 隧道 IP: ${vip_cidr}${plain}"
echo -e "${green}对端 IPIPv6 隧道 IP: ${remotevip}${plain}"

cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
After=network.target
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
systemctl enable rc-local &>/dev/null
systemctl start rc-local &>/dev/null
echo -e "${green}rc.local 服务已启用并启动。${plain}"

if ! iptables -t nat -C POSTROUTING -s "${remotevip}" -j MASQUERADE 2>/dev/null; then
iptables -t nat -A POSTROUTING -s "${remotevip}" -j MASQUERADE
echo -e "${green}已添加 iptables MASQUERADE 规则。${plain}"
fi

if ! sysctl net.ipv6.conf.all.forwarding | grep -q " = 1"; then
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf &>/dev/null
echo -e "${green}已启用 IPv6 转发。${plain}"
fi

if [[ $yn == "Y" ]]||[[ $yn == "y" ]]; then
echo -e "${red}提示:${plain}${yellow}你的机器是甲骨文，IPIPv6隧道生效，需要重启一次！${plain}"
fi

echo -e "${green}-------------------------------------------------------${plain}"
echo -e "${green}IPIPv6 隧道配置完成。请测试 ping6 ${remotevip}${plain}"
echo -e "${green}-------------------------------------------------------${plain}"
}

# --- WireGuard 服务相关功能函数 ---
manage_wg_services() {
clear
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${green} WireGuard 服务管理 ${plain}"
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${red}0.${plain} 返回主菜单"
echo -e "${green}1.${plain} 一键查看所有 WireGuard 接口"
echo -e "${green}2.${plain} 一键重启 WireGuard 接口"
echo -e "${green}3.${plain} 一键卸载 WireGuard 接口"
echo -e "${green}-----------------------------------------------------------${plain}"
echo -e "${yellow}请选择你要使用的功能${plain}"
read -p "请输入数字 :" wg_num

case "$wg_num" in
0)
return
;;
1)
view_wg_interfaces
;;
2)
reboot_wg_interface
;;
3)
uninstall_wg_interface
;;
*)
echo -e "${red}出现错误:请输入正确数字 ${plain}"
sleep 2s
;;
esac
read -p "按任意键返回 WireGuard 服务菜单..."
manage_wg_services
}

view_wg_interfaces() {
clear
echo -e "${blue}--- 已部署的 WireGuard 接口 ---${plain}"
local active_wg_interfaces=$(wg show interfaces 2>/dev/null)
local all_wg_config_files=(/etc/wireguard/*.conf)

if [[ -z "$active_wg_interfaces" && "${all_wg_config_files[0]}" == "/etc/wireguard/*.conf" ]]; then
echo -e "${yellow}未检测到任何 WireGuard 接口或配置文件。${plain}"
return
fi

if [[ -n "$active_wg_interfaces" ]]; then
echo -e "${green}--- 正在运行的 WireGuard 接口 ---${plain}"
echo "$active_wg_interfaces" | tr ' ' '\n' | while read -r iface; do
if [[ -n "$iface" ]]; then
echo -e "--- 接口: ${green}$iface${plain} ---"
wg show "$iface"
echo ""
fi
done
fi

if [[ "${all_wg_config_files[0]}" != "/etc/wireguard/*.conf" ]]; then
echo -e "${green}--- 所有 WireGuard 配置文件 (/etc/wireguard/*.conf) ---${plain}"
for config_file in "${all_wg_config_files[@]}"; do
local iface_name=$(basename "$config_file" .conf)
if ! echo "$active_wg_interfaces" | grep -q "\<$iface_name\>"; then
echo -e " ${yellow}配置文件: ${config_file} (未运行)${plain}"
fi
done
fi
}

select_wg_interface() {
local wg_config_files=(/etc/wireguard/*.conf)
local wg_list=()

for config_file in "${wg_config_files[@]}"; do
if [[ -f "$config_file" ]]; then
iface_name=$(basename "$config_file" .conf)
wg_list+=("$iface_name")
fi
done

if [[ ${#wg_list[@]} -eq 0 ]]; then
echo -e "${red}未找到任何 WireGuard 配置文件 (/etc/wireguard/*.conf)。${plain}" >&2
return 1
fi

PS3="请选择要操作的 WireGuard 接口 (输入数字): "
local selected_choice
select selected_choice in "${wg_list[@]}"; do
if [[ -n "$selected_choice" ]]; then
echo "$selected_choice"
return 0
else
echo -e "${red}无效的选择，请重新输入。${plain}" >&2
fi
done
return 1
}

reboot_wg_interface() {
clear
echo -e "${blue}--- 重启 WireGuard 接口 ---${plain}"
local chosen_wg_iface=$(select_wg_interface)
local select_status=$?

if [[ $select_status -ne 0 || -z "$chosen_wg_iface" ]]; then
echo -e "${red}接口选择失败，无法执行重启操作。${plain}"
return
fi

echo -e "${yellow}正在重启 WireGuard 接口 ${chosen_wg_iface}...${plain}"
wg-quick down "$chosen_wg_iface" &>/dev/null
if [ $? -ne 0 ]; then
echo -e "警告: 接口 ${chosen_wg_iface} 可能未运行或停止失败。尝试直接启动。"
fi
wg-quick up "$chosen_wg_iface" &>/dev/null
if [ $? -eq 0 ]; then
echo -e "${green}WireGuard 接口 ${chosen_wg_iface} 重启成功。${plain}"
else
echo -e "${red}WireGuard 接口 ${chosen_wg_iface} 重启失败。请检查配置文件或日志。${plain}"
fi
}

uninstall_wg_interface() {
clear
echo -e "${blue}--- 卸载 WireGuard 接口 ---${plain}"
local chosen_wg_iface=$(select_wg_interface)
local select_status=$?

if [[ $select_status -ne 0 || -z "$chosen_wg_iface" ]]; then
echo -e "${red}接口选择失败，无法执行卸载操作。${plain}"
return
fi
read -p "警告: 卸载 WireGuard 接口 ${chosen_wg_iface} 会中断其所有连接。确定要继续吗？(Y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
echo -e "${yellow}操作已取消。${plain}"
return
fi

uninstall_wg_interface_internal "$chosen_wg_iface"
}

uninstall_wg_interface_internal() {
local wg_iface="$1"
local config_file="/etc/wireguard/${wg_iface}.conf"

echo -e "${yellow}正在卸载 WireGuard 接口 ${wg_iface}...${plain}"
wg-quick down "$wg_iface" &>/dev/null
systemctl disable "wg-quick@${wg_iface}" &>/dev/null
systemctl stop "wg-quick@${wg_iface}" &>/dev/null
echo -e "${blue}WireGuard 服务已停止并禁用。${plain}"

local escaped_wg_iface=$(echo "$wg_iface" | sed 's/[][\/.^$*+?()|]/\\&/g')
sed -i "/wg-quick up ${escaped_wg_iface}/d" /etc/rc.local
if ! grep -q "^exit 0$" /etc/rc.local; then
echo "exit 0" >> /etc/rc.local
fi
systemctl daemon-reload &>/dev/null
systemctl restart rc-local &>/dev/null

if [[ -f "$config_file" ]]; then
rm "$config_file"
echo -e "${blue}WireGuard 配置文件 ${config_file} 已删除。${plain}"
fi

echo -e "${yellow}请手动检查 iptables 中是否有与此 WireGuard 接口相关的 POSTROUTING 或转发规则。${plain}"
echo -e "${yellow}通常 'wg-quick down' 命令会自动清理这些规则。${plain}"
echo -e "${yellow}如果需要手动检查: 'iptables -t nat -L --line-numbers' 或 'iptables -L --line-numbers'${plain}"
echo -e "${yellow}然后可以通过 'iptables -t nat -D POSTROUTING [行号]' 或 'iptables -D FORWARD [行号]' 来删除。${plain}"

echo -e "${green}WireGuard 接口 ${wg_iface} 已成功卸载。${plain}"
}

# --- 安装WireGuard 函数 ---
install_wg(){
local filename local_wg_cidr local_wg_ip remote_wg_ip remote_wg_publickey wgport remote_wg_ipip_endpoint_ip endpoint_str privatekey_path publickey_path localprivatekey config_file vpspublickey
echo -e "${blue}--- 正在部署 WireGuard 隧道 ---${plain}"

# 安装 WireGuard
if ! command -v wg &> /dev/null; then
apt-get update &>/dev/null
apt-get install wireguard -y &>/dev/null
echo -e "${green}WireGuard 及其依赖已安装。${plain}"
else
echo -e "${green}WireGuard 已安装。${plain}"
fi

privatekey_path="/etc/wireguard/privatekey"
publickey_path="/etc/wireguard/publickey"

if [[ ! -f $privatekey_path ]]; then
echo -e "${blue}正在生成 WireGuard 密钥对...${plain}"
wg genkey | tee $privatekey_path | wg pubkey | tee $publickey_path
chmod 600 $privatekey_path $publickey_path
echo -e "${green}密钥已生成并保存。${plain}"
else
echo -e "${green}复用现有 WireGuard 密钥。${plain}"
fi

localprivatekey=$(cat $privatekey_path)

echo -ne "${yellow}请输入要创建的 WireGuard 配置文件名 (例如 wg0, wg1):${plain}"
read filename

config_file="/etc/wireguard/${filename}.conf"

if [[ -f "$config_file" ]]; then
echo -e "${red}⚠️ 已存在同样名称的 WireGuard 配置文件 ${config_file}，程序退出，请重新执行程序。${plain}"
exit 1
fi

echo -ne "${yellow}请输入本机的 WireGuard 内部 IP 地址 (例如 10.0.0.2/24)：${plain}"
read local_wg_cidr

if echo "$local_wg_cidr" | grep -q ':'; then
if ! [[ "$local_wg_cidr" =~ ^([0-9a-fA-F:]+(/[0-9]{1,3})?)$ ]]; then
echo -e "${red}错误: 请输入有效的 IPv6 CIDR，如 fdf1::2/64${plain}"
exit 1
fi
else
if ! [[ "$local_wg_cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
echo -e "${red}错误: 请输入有效的 IPv4 CIDR，如 10.0.0.2/24${plain}"
exit 1
fi
fi

local_wg_ip=$(echo "$local_wg_cidr" | cut -d'/' -f1)

echo -ne "${yellow}请输入对端的 WireGuard 内部 IP 地址 (例如 10.0.0.1)：${plain}"
read remote_wg_ip
echo -ne "${yellow}请输入对端的 WireGuard 公钥内容:${plain}"
read remote_wg_publickey
echo -ne "${yellow}请输入 WireGuard 监听端口 (如：59866):${plain}"
read wgport

if ! [[ "$wgport" =~ ^[0-9]+$ ]] || [ "$wgport" -lt 1 ] || [ "$wgport" -gt 65535 ]; then
echo -e "${red}错误: 请输入有效的端口号 (1-65535)${plain}"
exit 1
fi

echo -ne "${yellow}请输入对端 WireGuard Endpoint 的 IPIP 隧道地址 (例如 192.168.100.1 或 fdef:1::2):${plain}"
read remote_wg_ipip_endpoint_ip

local endpoint_str="${remote_wg_ipip_endpoint_ip}:${wgport}"
if echo "$remote_wg_ipip_endpoint_ip" | grep -q ':'; then
endpoint_str="[${remote_wg_ipip_endpoint_ip}]:${wgport}"
fi

echo -e "${blue}正在创建 WireGuard 配置文件 ${config_file} ...${plain}"
cat > "$config_file" <<EOF
[Interface]
Address = ${local_wg_cidr}
ListenPort = ${wgport}
PrivateKey = ${localprivatekey}

[Peer]
PublicKey = ${remote_wg_publickey}
AllowedIPs = ${remote_wg_ip}/32
Endpoint = ${endpoint_str}
PersistentKeepalive = 25
EOF

chmod 600 "$config_file"

ensure_rc_local

echo -e "${blue}正在更新 /etc/rc.local 文件以实现 WireGuard 开机自启...${plain}"
if ! grep -q "wg-quick up ${filename}" /etc/rc.local; then
sed -i '/^exit 0$/d' /etc/rc.local
echo "wg-quick up $filename" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
fi

echo -e "${blue}正在启动 WireGuard 接口 ${filename}...${plain}"
if wg-quick up "$filename" &>/dev/null; then
systemctl enable "wg-quick@${filename}" &>/dev/null
systemctl start "wg-quick@${filename}" &>/dev/null
if systemctl is-active --quiet "wg-quick@${filename}"; then
echo -e "${green}WireGuard 接口 ${filename} 已启动并已设置为开机自启动。${plain}"
else
echo -e "${red}WireGuard 服务启动失败，请查看日志: journalctl -u wg-quick@${filename} -n 50${plain}"
exit 1
fi
echo -e "${blue}当前接口状态：${plain}"
wg show "$filename" | head -n 4
else
echo -e "${red}WireGuard 接口启动失败，请检查配置文件语法或端口占用情况。${plain}"
exit 1
fi

vpspublickey=$(cat $publickey_path)

echo -e "${green}------------------------------------------------------------${plain}"
echo -e "${green}WireGuard 配置文件 ${config_file} 已创建并启动。${plain}\n"
echo -e "${green}请在对端设备上的 WireGuard 配置中添加以下信息：${plain}"
echo -e " ${green}Peer Public key 填写：${yellow}${vpspublickey}${plain}"
echo -e " ${green}Peer AllowedIPs 填写：${yellow}${local_wg_ip}/32${plain}"
echo -e " ${green}Peer Endpoint 填写：${yellow}${endpoint_str}${plain}"
echo -e " ${green}WireGuard ListenPort (如果对端也监听此隧道) : ${yellow}${wgport}${plain}\n"
echo -e "${green}请确保对端 WireGuard 配置中的 Endpoint IP 是您本机 IPIP 隧道接口的地址。${plain}"
echo -e "${red}重要提示：此配置模板不包含 iptables MASQUERADE 规则。如果您的 WireGuard 隧道需要转发互联网流量，请手动配置 SNAT 或其他转发规则。${plain}"
echo -e "${green}------------------------------------------------------------${plain}"

if echo "$local_wg_ip" | grep -q ':'; then
echo -e "${green}请执行 'ping6 ${remote_wg_ip}' 测试 WireGuard 隧道连通性。${plain}"
else
echo -e "${green}请执行 'ping ${remote_wg_ip}' 测试 WireGuard 隧道连通性。${plain}"
fi
}

# =========================================================
# --- Gost 服务相关功能函数 ---
# =========================================================

function checknew() {
local checknew
checknew=$(gost -V 2>&1 | awk '{print $2}')
echo "你的gost版本为: $checknew"
echo -n "是否更新(y/n):"
read checknewnum
if test "$checknewnum" = "y"; then
cp -r /etc/gost /tmp/
Install_ct
rm -rf /etc/gost
mv /tmp/gost /etc/
systemctl restart gost
else
return
fi
}

function Installation_dependency() {
if ! command -v gzip &> /dev/null; then
if [[ ${release} == "centos" ]]; then
yum update -y
yum install -y gzip wget
else
apt-get update -y
apt-get install -y gzip wget
fi
fi
}

function check_new_ver() {
ct_new_ver="2.11.2" # 固定版本
echo -e "${Info} gost 使用稳定版本 ${ct_new_ver}"
}

function check_file() {
if [[ ! -d "/usr/lib/systemd/system/" ]]; then
mkdir -p /usr/lib/systemd/system
chmod 755 /usr/lib/systemd/system
fi
}

function check_nor_file() {
rm -rf ./gost ./gost.service ./config.json
rm -rf /etc/gost /usr/lib/systemd/system/gost.service /usr/bin/gost
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
wget --no-check-certificate -O gost-linux-"$bit"-"$ct_new_ver".gz https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost-linux-"$bit"-"$ct_new_ver".gz
else
wget --no-check-certificate -O gost-linux-"$bit"-"$ct_new_ver".gz https://github.com/ginuerzh/gost/releases/download/v"$ct_new_ver"/gost-linux-"$bit"-"$ct_new_ver".gz
fi

gunzip gost-linux-"$bit"-"$ct_new_ver".gz
mv gost-linux-"$bit"-"$ct_new_ver" /usr/bin/gost
chmod 755 /usr/bin/gost

if [[ ${addyn} == [Yy] ]]; then
wget --no-check-certificate -O /usr/lib/systemd/system/gost.service https://gotunnel.oss-cn-shenzhen.aliyuncs.com/gost.service
else
wget --no-check-certificate -O /usr/lib/systemd/system/gost.service https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.service
fi
chmod 644 /usr/lib/systemd/system/gost.service

mkdir -p /etc/gost
if [[ ${addyn} == [Yy] ]]; then
wget --no-check-certificate -O /etc/gost/config.json https://gotunnel.oss-cn-shenzhen.aliyuncs.com/config.json
else
wget --no-check-certificate -O /etc/gost/config.json https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/config.json
fi
chmod 600 /etc/gost/config.json
chmod 600 "$raw_conf_path" 2>/dev/null || touch "$raw_conf_path" && chmod 600 "$raw_conf_path"

systemctl daemon-reload
systemctl enable gost
systemctl restart gost

if systemctl is-active --quiet gost && [[ -f /usr/bin/gost ]] && [[ -f /etc/gost/config.json ]]; then
echo -e "${green}gost安装成功${plain}"
rm -f ./gost-linux-* ./gost ./gost.service ./config.json
else
echo -e "${red}gost安装失败，请检查日志: journalctl -u gost -n 50${plain}"
rm -f ./gost-linux-* ./gost ./gost.service ./config.json
exit 1
fi
}

function Uninstall_ct() {
systemctl stop gost &>/dev/null
systemctl disable gost &>/dev/null
rm -f /usr/bin/gost
rm -f /usr/lib/systemd/system/gost.service
rm -rf /etc/gost
echo -e "${green}gost已经成功删除${plain}"
}

function Start_ct() {
systemctl start gost
if systemctl is-active --quiet gost; then
echo -e "${green}Gost 已启动${plain}"
else
echo -e "${red}Gost 启动失败，请查看日志${plain}"
fi
}

function Stop_ct() {
systemctl stop gost
echo -e "${green}Gost 已停止${plain}"
}

function Restart_ct() {
if [[ ! -f "$raw_conf_path" ]]; then
mkdir -p /etc/gost
touch "$raw_conf_path"
chmod 600 "$raw_conf_path"
fi

rm -f "$gost_conf_path"
confstart
writeconf
conflast

# 校验 JSON 是否合法
if command -v jq &> /dev/null; then
if ! jq . "$gost_conf_path" >/dev/null 2>&1; then
echo -e "${red}Gost 配置文件格式错误，请检查：${plain}"
jq . "$gost_conf_path" 2>&1
return 1
fi
fi

systemctl restart gost
if systemctl is-active --quiet gost; then
echo -e "${green}Gost 已重读配置并重启${plain}"
else
echo -e "${red}Gost 重启失败，请查看日志: journalctl -u gost -n 50${plain}"
return 1
fi
}

function Remove_ct() {
if [[ ! -f "$raw_conf_path" ]]; then
echo -e "$Error $raw_conf_path 配置文件不存在。"
return
fi
if [[ ! -s "$raw_conf_path" ]]; then
echo -e "$Error $raw_conf_path 配置文件为空，没有可删除的配置。"
return
fi

echo -e "$Info 当前Gost配置如下："
show_all_conf
read -p "请输入要删除的配置序号: " del_num
if [[ ! "$del_num" =~ ^[0-9]+$ ]]; then
echo -e "$Error 无效的数字。"
return
fi

local count_line=$(awk 'END{print NR}' $raw_conf_path)
if (( del_num < 1 || del_num > count_line )); then
echo -e "$Error 序号超出范围 (1-$count_line)。"
return
fi

echo -e "${yellow}正在删除第 $del_num 条配置...${plain}"
sed -i "${del_num}d" "$raw_conf_path"

echo -e "${green}配置已删除。${plain}"

if [[ -s "$raw_conf_path" ]]; then
echo -e "$Info 新的Gost配置如下："
show_all_conf
else
echo -e "$Info 所有配置均已删除。"
fi

read -p "是否立即重启Gost以应用更改? (y/n): " confirm_restart
if [[ "$confirm_restart" == "y" || "$confirm_restart" == "Y" ]]; then
Restart_ct
else
echo -e "$yellow Gost未重启。您需要稍后手动重启 (选项6) 才能使删除生效。${plain}"
fi
}

function read_protocol() {
echo -e "请问您要设置哪种功能: "
echo -e "-----------------------------------"
echo -e "[1] tcp+udp流量转发, 不加密"
echo -e "[2] 加密隧道流量转发"
echo -e "[3] 解密由gost传输而来的流量并转发"
echo -e "[4] 一键安装ss/socks5/http代理"
echo -e "[5] 进阶：多落地均衡负载"
echo -e "[6] 进阶：转发CDN自选节点"
echo -e "-----------------------------------"
read -p "请选择: " numprotocol

case "$numprotocol" in
1) flag_a="nonencrypt" ;;
2) encrypt ;;
3) decrypt ;;
4) proxy ;;
5) enpeer ;;
6) cdn ;;
*) echo -e "${red}type error, please try again${plain}"; return 1 ;;
esac
}

function read_s_port() {
case "$flag_a" in
ss|socks|http)
echo -e "-----------------------------------"
read -p "请输入密码: " flag_b
;;
*)
echo -e "------------------------------------------------------------------"
read -p "请输入本地监听端口: " flag_b
;;
esac
}

function read_d_ip() {
case "$flag_a" in
ss)
echo -e "请选择ss加密方式:"
echo -e "[1] aes-256-gcm [2] aes-256-cfb [3] chacha20-ietf-poly1305 [4] chacha20 [5] rc4-md5 [6] AEAD_CHACHA20_POLY1305"
read -p "请选择: " ssencrypt
case "$ssencrypt" in
1) flag_c="aes-256-gcm" ;;
2) flag_c="aes-256-cfb" ;;
3) flag_c="chacha20-ietf-poly1305" ;;
4) flag_c="chacha20" ;;
5) flag_c="rc4-md5" ;;
6) flag_c="AEAD_CHACHA20_POLY1305" ;;
*) echo "错误"; return 1 ;;
esac
;;
socks|http)
read -p "请输入用户名: " flag_c
;;
peer*)
read -e -p "请输入落地列表文件名 (如 ips1): " flag_c
touch "$HOME/$flag_c.txt"
echo -e "请依次输入落地IP:端口"
while true; do
read -p "IP或域名: " peer_ip
read -p "端口: " peer_port
echo "$peer_ip:$peer_port" >> "$HOME/$flag_c.txt"
read -e -p "继续添加？[Y/n]:" addyn
[[ -z ${addyn} ]] && addyn="y"
[[ ${addyn} == [Nn] ]] && break
done
;;
cdn*)
read -p "请输入目标IP: " flag_c
echo -e "[1] 80 [2] 443 [3] 自定义"
read -p "请选择端口: " cdnport
case "$cdnport" in
1) flag_c="$flag_c:80" ;;
2) flag_c="$flag_c:443" ;;
3) read -p "自定义端口: " p; flag_c="$flag_c:$p" ;;
*) echo "错误"; return 1 ;;
esac
;;
*)
if [[ ${is_cert} == [Yy] ]]; then
echo -e "注意: 落地机开启自定义tls证书，务必填写${red}域名${plain}"
fi
read -p "请输入目标地址: " flag_c
;;
esac
}

function read_d_port() {
case "$flag_a" in
ss|socks|http)
read -p "请输入服务端口: " flag_d
;;
peer*)
echo -e "选择负载策略: [1] round [2] random [3] fifo"
read -p "请选择: " numstra
case "$numstra" in
1) flag_d="round" ;;
2) flag_d="random" ;;
3) flag_d="fifo" ;;
*) echo "错误"; return 1 ;;
esac
;;
cdn*)
read -p "请输入host: " flag_d
;;
*)
read -p "请输入目标端口: " flag_d
[[ ${is_cert} == [Yy] ]] && flag_d="$flag_d?secure=true"
;;
esac
}

function writerawconf() {
mkdir -p /etc/gost
echo "$flag_a/$flag_b#$flag_c#$flag_d" >> "$raw_conf_path"
chmod 600 "$raw_conf_path"
}

function rawconf() {
mkdir -p /etc/gost
touch "$raw_conf_path"
chmod 600 "$raw_conf_path"

set -e
read_protocol
read_s_port
read_d_ip
read_d_port
set +e

if [[ -z "$flag_a" ]]; then
echo -e "${red}配置过程中断，未添加任何配置。${plain}"
return
fi

writerawconf
echo -e "${green}配置已添加。${plain}"
read -p "是否立即重启Gost以应用更改? (y/n): " confirm_restart
if [[ "$confirm_restart" == "y" || "$confirm_restart" == "Y" ]]; then
Restart_ct
else
echo -e "$yellow Gost未重启。您需要稍后手动重启 (选项6) 才能使新配置生效。${plain}"
fi
}

function eachconf_retrieve() {
local trans_conf="$1"
d_server=${trans_conf#*#}
d_port=${d_server#*#}
d_ip=${d_server%#*}
flag_s_port=${trans_conf%%#*}
s_port=${flag_s_port#*/}
is_encrypt=${flag_s_port%/*}
}

function confstart() {
cat > "$gost_conf_path" <<EOF
{
"Debug": true,
"Retries": 0,
"ServeNodes": [
EOF
}

function multiconfstart() {
echo " {
\"Retries\": 0,
\"ServeNodes\": [" >> "$gost_conf_path"
}

function conflast() {
echo " ]
}" >> "$gost_conf_path"
}

function multiconflast() {
if [ $i -eq $count_line ]; then
echo " ]
}" >> "$gost_conf_path"
else
echo " ]
}," >> "$gost_conf_path"
fi
}

function encrypt() {
echo -e "选择传输类型: [1] tls [2] ws [3] wss"
read -p "请选择: " numencrypt
case "$numencrypt" in
1) flag_a="encrypttls" ;;
2) flag_a="encryptws" ;;
3) flag_a="encryptwss" ;;
*) echo "错误"; return 1 ;;
esac
if [[ "$flag_a" == "encrypttls" || "$flag_a" == "encryptwss" ]]; then
echo -e "注意: 选择 是 将针对落地的自定义证书开启证书校验保证安全性，稍后落地机务必填写${red}域名${plain}"
read -e -p "落地机是否开启了自定义tls证书？[y/n]:" is_cert
fi
}

function enpeer() {
echo -e "选择传输类型: [1] 不加密 [2] tls [3] ws [4] wss"
read -p "请选择: " numpeer
case "$numpeer" in
1) flag_a="peerno" ;;
2) flag_a="peertls" ;;
3) flag_a="peerws" ;;
4) flag_a="peerwss" ;;
*) echo "错误"; return 1 ;;
esac
}

function cdn() {
echo -e "选择传输类型: [1] 不加密 [2] ws [3] wss"
read -p "请选择: " numcdn
case "$numcdn" in
1) flag_a="cdnno" ;;
2) flag_a="cdnws" ;;
3) flag_a="cdnwss" ;;
*) echo "错误"; return 1 ;;
esac
}

function cert() {
echo -e "[1] ACME申请证书 [2] 手动上传证书"
read -p "请选择: " numcert
if [[ "$numcert" == "1" ]]; then
check_sys
if ! command -v socat &> /dev/null; then
if [[ ${release} == "centos" ]]; then
yum install -y socat
else
apt-get install -y socat
fi
fi
read -p "ZeroSSL邮箱: " zeromail
read -p "域名: " domain
curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --set-default-ca --server zerossl
~/.acme.sh/acme.sh --register-account -m "$zeromail" --server zerossl
echo -e "[1] HTTP申请 [2] Cloudflare DNS"
read -p "请选择: " certmethod
if [[ "$certmethod" == "1" ]]; then
~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --force
else
read -p "CF邮箱: " cfmail
read -p "CF API Key: " cfkey
export CF_Key="$cfkey"
export CF_Email="$cfmail"
~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" --standalone -k ec-256 --force
fi
mkdir -p "$HOME/gost_cert"
~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath "$HOME/gost_cert/cert.pem" --keypath "$HOME/gost_cert/key.pem" --ecc --force
echo -e "${green}证书安装成功，位于 $HOME/gost_cert${plain}"
elif [[ "$numcert" == "2" ]]; then
mkdir -p "$HOME/gost_cert"
echo -e "请将 cert.pem 和 key.pem 上传至 $HOME/gost_cert 目录"
else
echo "错误"
return 1
fi
}

function decrypt() {
echo -e "选择解密类型: [1] tls [2] ws [3] wss"
read -p "请选择: " numdecrypt
case "$numdecrypt" in
1) flag_a="decrypttls" ;;
2) flag_a="decryptws" ;;
3) flag_a="decryptwss" ;;
*) echo "错误"; return 1 ;;
esac
}

function proxy() {
echo -e "选择代理类型: [1] ss [2] socks5 [3] http"
read -p "请选择: " numproxy
case "$numproxy" in
1) flag_a="ss" ;;
2) flag_a="socks" ;;
3) flag_a="http" ;;
*) echo "错误"; return 1 ;;
esac
}

function method() {
local i="$1" is_encrypt="$2" s_port="$3" d_ip="$4" d_port="$5"
if [ $i -eq 1 ]; then
case "$is_encrypt" in
nonencrypt)
echo " \"tcp://:$s_port/$d_ip:$d_port\",
\"udp://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
;;
cdnno)
echo " \"tcp://:$s_port/$d_ip?host=$d_port\",
\"udp://:$s_port/$d_ip?host=$d_port\"" >> "$gost_conf_path"
;;
peerno)
echo " \"tcp://:$s_port?ip=$HOME/$d_ip.txt&strategy=$d_port\",
\"udp://:$s_port?ip=$HOME/$d_ip.txt&strategy=$d_port\"" >> "$gost_conf_path"
;;
encrypttls|encryptws|encryptwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#encrypt}://$d_ip:$d_port"
EOF
;;
peertls|peerws|peerwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#peer}://:?ip=$HOME/$d_ip.txt&strategy=$d_port"
EOF
;;
cdnws|cdnwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#cdn}://$d_ip?host=$d_port"
EOF
;;
decrypttls|decryptwss)
if [[ -d "$HOME/gost_cert" ]]; then
echo " \"relay+${is_encrypt#decrypt}://:$s_port/$d_ip:$d_port?cert=$HOME/gost_cert/cert.pem&key=$HOME/gost_cert/key.pem\"" >> "$gost_conf_path"
else
echo " \"relay+${is_encrypt#decrypt}://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
fi
;;
decryptws)
echo " \"relay+ws://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
;;
ss|socks|http)
echo " \"${flag_a}://$d_ip:$s_port@:$d_port\"" >> "$gost_conf_path"
;;
*)
echo "config error"
;;
esac
else
case "$is_encrypt" in
nonencrypt)
echo " \"tcp://:$s_port/$d_ip:$d_port\",
\"udp://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
;;
peerno)
echo " \"tcp://:$s_port?ip=$HOME/$d_ip.txt&strategy=$d_port\",
\"udp://:$s_port?ip=$HOME/$d_ip.txt&strategy=$d_port\"" >> "$gost_conf_path"
;;
cdnno)
echo " \"tcp://:$s_port/$d_ip?host=$d_port\",
\"udp://:$s_port/$d_ip?host=$d_port\"" >> "$gost_conf_path"
;;
encrypttls|encryptws|encryptwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#encrypt}://$d_ip:$d_port"
EOF
;;
peertls|peerws|peerwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#peer}://:?ip=$HOME/$d_ip.txt&strategy=$d_port"
EOF
;;
cdnws|cdnwss)
cat >> "$gost_conf_path" <<EOF
"tcp://:$s_port",
"udp://:$s_port"
],
"ChainNodes": [
"relay+${is_encrypt#cdn}://$d_ip?host=$d_port"
EOF
;;
decrypttls|decryptwss)
if [[ -d "$HOME/gost_cert" ]]; then
echo " \"relay+${is_encrypt#decrypt}://:$s_port/$d_ip:$d_port?cert=$HOME/gost_cert/cert.pem&key=$HOME/gost_cert/key.pem\"" >> "$gost_conf_path"
else
echo " \"relay+${is_encrypt#decrypt}://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
fi
;;
decryptws)
echo " \"relay+ws://:$s_port/$d_ip:$d_port\"" >> "$gost_conf_path"
;;
ss|socks|http)
echo " \"${flag_a}://$d_ip:$s_port@:$d_port\"" >> "$gost_conf_path"
;;
*)
echo "config error"
;;
esac
fi
}

function writeconf() {
if [[ ! -r "$raw_conf_path" ]]; then
return
fi

local count_line=$(awk 'END{print NR}' "$raw_conf_path")
if [[ $count_line -eq 0 ]]; then
return
fi

confstart

for ((i = 1; i <= $count_line; i++)); do
local trans_conf=$(sed -n "${i}p" "$raw_conf_path")
eachconf_retrieve "$trans_conf"
if [ $i -eq 1 ]; then
method 1 "$is_encrypt" "$s_port" "$d_ip" "$d_port"
elif [ $i -eq 2 ]; then
echo " ],
\"Routes\": [" >> "$gost_conf_path"
multiconfstart
method 2 "$is_encrypt" "$s_port" "$d_ip" "$d_port"
multiconflast
else
multiconfstart
method 2 "$is_encrypt" "$s_port" "$d_ip" "$d_port"
multiconflast
fi
done

conflast
}

function show_all_conf() {
if [[ ! -f "$raw_conf_path" || ! -s "$raw_conf_path" ]]; then
echo -e "${yellow}Gost 原始配置文件为空或不存在。${plain}"
return
fi

echo -e " ${green}GOST 配置${plain} "
echo -e "--------------------------------------------------------"
echo -e "序号|方法 |本地端口 |目的地地址:目的地端口"
echo -e "--------------------------------------------------------"

local count_line=$(awk 'END{print NR}' "$raw_conf_path")
for ((i = 1; i <= $count_line; i++)); do
local trans_conf=$(sed -n "${i}p" "$raw_conf_path")
eachconf_retrieve "$trans_conf"

case "$is_encrypt" in
nonencrypt) str="不加密中转" ;;
encrypttls) str=" tls隧道 " ;;
encryptws) str=" ws隧道 " ;;
encryptwss) str=" wss隧道 " ;;
peerno) str=" 不加密均衡负载 " ;;
peertls) str=" tls隧道均衡负载 " ;;
peerws) str=" ws隧道均衡负载 " ;;
peerwss) str=" wss隧道均衡负载 " ;;
decrypttls) str=" tls解密 " ;;
decryptws) str=" ws解密 " ;;
decryptwss) str=" wss解密 " ;;
ss) str=" ss " ;;
socks) str=" socks5 " ;;
http) str=" http " ;;
cdnno) str="不加密转发CDN" ;;
cdnws) str="ws隧道转发CDN" ;;
cdnwss) str="wss隧道转发CDN" ;;
*) str="未知配置" ;;
esac

printf " %-3s| %-12s | %-8s | %s:%s\n" "$i" "$str" "$s_port" "$d_ip" "$d_port"
echo -e "--------------------------------------------------------"
done
}

function cron_restart() {
echo -e "选择: [1] 配置 [2] 删除"
read -p "请选择: " numcron
case "$numcron" in
1)
echo -e "[1] 每小时 [2] 每日定点"
read -p "请选择: " numcrontype
case "$numcrontype" in
1)
read -p "每几小时重启: " cronhr
(crontab -l 2>/dev/null | grep -v "systemctl restart gost") | crontab -
(crontab -l 2>/dev/null; echo "0 */${cronhr} * * * systemctl restart gost") | crontab -
;;
2)
read -p "每日几点重启(0-23): " cronhr
(crontab -l 2>/dev/null | grep -v "systemctl restart gost") | crontab -
(crontab -l 2>/dev/null; echo "0 ${cronhr} * * * systemctl restart gost") | crontab -
;;
*) echo "错误"; return 1 ;;
esac
echo -e "${green}定时重启设置成功！${plain}"
;;
2)
(crontab -l 2>/dev/null | grep -v "systemctl restart gost") | crontab -
echo -e "${green}定时重启任务删除完成！${plain}"
;;
*) echo "错误"; return 1 ;;
esac
}

function update_sh() {
local ol_version
ol_version=$(curl -L -s --connect-timeout 5 https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
if [[ -n "$ol_version" && "$shell_version" != "$ol_version" ]]; then
echo -e "${yellow}发现新版本 v${ol_version}，是否更新？[Y/N]${plain}"
read -r update_confirm
if [[ "$update_confirm" =~ ^[Yy] ]]; then
wget -O "$0" --no-check-certificate https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh
echo -e "${green}更新完成，请重新运行脚本。${plain}"
exit 0
fi
else
echo -e "${green}当前已是最新版本。${plain}"
fi
}

# =========================================================
# --- Gost 管理菜单 ---
# =========================================================
manage_gost_services() {
while true; do
clear
echo && echo -e " Gost (v${ct_new_ver}) 一键安装配置脚本 ${red}[v${shell_version}]${plain}
特性: (1) 采用 systemd + 配置文件管理
(2) 支持多条规则同时生效
(3) 重启不失效
功能: TCP/UDP/SS/Socks5/HTTP/TLS/WS/WSS/负载均衡/CDN/证书
文档：https://github.com/KANIKIG/Multi-EasyGost
${yellow}-----------------------------------------------------------${plain}
${red}0.${plain} 返回主菜单
${yellow}-----------------------------------------------------------${plain}
${green}1.${plain} 安装 Gost
${green}2.${plain} 更新 Gost
${green}3.${plain} 卸载 Gost
${yellow}-----------------------------------------------------------${plain}
${green}4.${plain} 启动 Gost
${green}5.${plain} 停止 Gost
${green}6.${plain} 重启 Gost (重载配置)
${yellow}-----------------------------------------------------------${plain}
${green}7.${plain} 新增 Gost 转发配置
${green}8.${plain} 查看现有 Gost 配置
${green}9.${plain} 删除一则 Gost 配置
${yellow}-----------------------------------------------------------${plain}
${green}10.${plain} Gost 定时重启配置
${green}11.${plain} 自定义 TLS 证书配置
${green}12.${plain} 检查脚本更新
${yellow}-----------------------------------------------------------${plain}" && echo
read -e -p " 请输入数字 [0-12]:" num
case "$num" in
0) return ;;
1) Install_ct ;;
2) checknew ;;
3) Uninstall_ct ;;
4) Start_ct ;;
5) Stop_ct ;;
6) Restart_ct ;;
7) rawconf ;;
8) show_all_conf ;;
9) Remove_ct ;;
10) cron_restart ;;
11) cert ;;
12) update_sh ;;
*) echo -e "${red}请输入正确数字 [0-12]${plain}" ;;
esac
read -p "按任意键返回 Gost 管理菜单..."
done
}

# =========================================================
# --- 帮助菜单 ---
# =========================================================
show_help() {
clear
cat <<EOF
${green}=== 综合隧道管理脚本帮助 ===${plain}

本脚本支持一键部署和管理 IPIP/WireGuard/Gost 隧道。

🔹 安装类 (1-3):
1. IPIPv4 隧道 —— 用于 IPv4 跨网段打通
2. IPIPv6 隧道 —— 用于 IPv6 跨网段打通
3. WireGuard —— 高性能加密隧道，常配合 IPIP 使用

🔹 管理类 (4-6):
4. IPIP 服务管理 —— 查看、重启、卸载已部署隧道
5. WireGuard 管理 —— 同上
6. Gost 管理 —— 支持 TCP/UDP/SS/Socks5/HTTP/TLS/WS/WSS 转发、负载均衡、CDN、证书等

📌 部署顺序建议：
1. 先部署 IPIP 隧道（选1或2）
2. 再部署 WireGuard（选3），Endpoint 填写 IPIP 内部IP
3. 最后用 Gost（选6）做高级流量转发


按任意键返回...
EOF
read -n 1
}

# =========================================================
# --- 综合主菜单 ---
# =========================================================
main_menu() {
while true; do
clear
echo -e "${green}=======================================================${plain}"
echo -e "${blue} 综合隧道管理脚本 ${plain}"
echo -e "${green}=======================================================${plain}"
echo -e " ${green}1.${plain} 安装 IPIP (IPv4) 隧道"
echo -e " ${green}2.${plain} 安装 IPIP (IPv6) 隧道"
echo -e " ${green}3.${plain} 安装 WireGuard 隧道"
echo -e "${green}-------------------------------------------------------${plain}"
echo -e " ${blue}4.${plain} IPIP 服务管理 (查看/重启/卸载)"
echo -e " ${blue}5.${plain} WireGuard 服务管理 (查看/重启/卸载)"
echo -e " ${blue}6.${plain} Gost (v2.11.2) 服务管理 (安装/配置/管理)"
echo -e "${green}-------------------------------------------------------${plain}"
echo -e " ${blue}h.${plain} 显示帮助信息"
echo -e " ${red}0.${plain} 退出脚本"
echo -e "${green}=======================================================${plain}"
read -p "请输入数字 [0-6 或 h]: " main_num

case "$main_num" in
1) install_ipip; read -p "按任意键返回主菜单...";;
2) install_ipipv6; read -p "按任意键返回主菜单...";;
3) install_wg; read -p "按任意键返回主菜单...";;
4) manage_ipip_services;;
5) manage_wg_services;;
6) manage_gost_services;;
h|H) show_help;;
0) exit 0;;
*) echo -e "${red}出现错误:请输入正确数字 [0-6 或 h]${plain}"; sleep 2s;;
esac
done
}

# --- 脚本执行入口 ---
check_root
main_menu
