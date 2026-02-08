#!/usr/bin/env bash
set -euo pipefail

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="1.2.0-opt"

Green="\033[32m"; Red="\033[31m"; GreenBg="\033[42;37m"; RedBg="\033[41;37m"; NC="\033[0m"
Info="${Green}[信息]${NC}"
Error="${Red}[错误]${NC}"
Tip="${Green}[注意]${NC}"

release=""

need_root(){
  if [[ ${EUID} -ne 0 ]]; then
    echo -e "${Error} 需要root权限运行：sudo bash $0"
    exit 1
  fi
}

check_sys(){
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif grep -qiE "debian" /etc/issue 2>/dev/null || grep -qiE "debian" /proc/version 2>/dev/null; then
    release="debian"
  elif grep -qiE "ubuntu" /etc/issue 2>/dev/null || grep -qiE "ubuntu" /proc/version 2>/dev/null; then
    release="ubuntu"
  elif grep -qiE "centos|red hat|redhat" /etc/issue 2>/dev/null || grep -qiE "centos|red hat|redhat" /proc/version 2>/dev/null; then
    release="centos"
  else
    release="unknown"
  fi
}

check_iptables(){
  if ! command -v iptables >/dev/null 2>&1; then
    echo -e "${Error} 没有安装iptables，请先安装！"
    exit 1
  fi
}

install_iptables(){
  if command -v iptables >/dev/null 2>&1; then
    echo -e "${Info} 已安装 iptables，继续..."
  else
    echo -e "${Info} 检测到未安装 iptables，开始安装..."
    if [[ ${release} == "centos" ]]; then
      yum -y update
      yum -y install iptables iptables-services
    else
      apt-get update -y
      apt-get install -y iptables
    fi
  fi

  echo -e "${Info} 开启转发并设置持久化..."
  set_ip_forward
  persist_iptables_hint
  echo -e "${Info} 初始化完成！"
}

set_ip_forward(){
  # 幂等写入
  if ! grep -qE '^net\.ipv4\.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

# 获取默认出口IP（更贴近真实网卡IP）
detect_local_ip(){
  local ip=""
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return
  fi
  # 退回公网探测
  ip=$(wget -qO- -t1 -T2 ipinfo.io/ip 2>/dev/null || true)
  echo "$ip"
}

is_port_range(){
  [[ "$1" =~ ^[0-9]{1,5}-[0-9]{1,5}$ ]]
}

is_port_single(){
  [[ "$1" =~ ^[0-9]{1,5}$ ]]
}

validate_port(){
  local p="$1"
  if is_port_single "$p"; then
    (( p>=1 && p<=65535 )) || return 1
  elif is_port_range "$p"; then
    local a b
    a="${p%-*}"; b="${p#*-}"
    (( a>=1 && a<=65535 && b>=1 && b<=65535 && a<=b )) || return 1
  else
    return 1
  fi
}

Set_forwarding_port(){
  read -r -e -p "请输入 远程端口 [1-65535] (支持端口段 2333-6666，被转发服务器): " forwarding_port
  [[ -z "${forwarding_port}" ]] && echo "取消..." && exit 1
  validate_port "${forwarding_port}" || { echo -e "${Error} 端口格式错误"; exit 1; }
  echo -e "\n\t远程端口: ${Red}${forwarding_port}${NC}\n"
}

Set_forwarding_ip(){
  read -r -e -p "请输入 被转发服务器IP: " forwarding_ip
  [[ -z "${forwarding_ip}" ]] && echo "取消..." && exit 1
  echo -e "\n\t被转发IP: ${Red}${forwarding_ip}${NC}\n"
}

Set_local_port(){
  echo -e "请输入 本地监听端口 [1-65535] (支持端口段 2333-6666)"
  read -r -e -p "(默认: ${forwarding_port}): " local_port
  [[ -z "${local_port}" ]] && local_port="${forwarding_port}"
  validate_port "${local_port}" || { echo -e "${Error} 端口格式错误"; exit 1; }
  echo -e "\n\t本地监听端口: ${Red}${local_port}${NC}\n"
}

Set_local_ip(){
  local auto_ip
  auto_ip="$(detect_local_ip)"
  read -r -e -p "请输入 本机出口网卡IP(回车自动检测: ${auto_ip:-空}): " local_ip
  if [[ -z "${local_ip}" ]]; then
    local_ip="${auto_ip}"
  fi
  [[ -z "${local_ip}" ]] && { echo -e "${Error} 自动检测失败，请手动输入"; exit 1; }
  echo -e "\n\t本机IP: ${Red}${local_ip}${NC}\n"
}

Set_forwarding_type(){
  echo -e "选择转发协议:
 1. TCP
 2. UDP
 3. TCP+UDP\n"
  read -r -e -p "(默认: 3): " forwarding_type_num
  [[ -z "${forwarding_type_num}" ]] && forwarding_type_num="3"
  case "$forwarding_type_num" in
    1) forwarding_type="TCP" ;;
    2) forwarding_type="UDP" ;;
    *) forwarding_type="TCP+UDP" ;;
  esac
}

Set_Config(){
  Set_forwarding_port
  Set_forwarding_ip
  Set_local_port
  Set_local_ip
  Set_forwarding_type

  echo -e "——————————————————————————————
请检查配置：\n
本地监听端口 : ${Green}${local_port}${NC}
本机IP       : ${Green}${local_ip}${NC}

远程端口     : ${Green}${forwarding_port}${NC}
远程IP       : ${Green}${forwarding_ip}${NC}
协议         : ${Green}${forwarding_type}${NC}
——————————————————————————————"
  read -r -e -p "回车继续（或 Ctrl+C 取消）: " _
}

# 端口段 DNAT 需要 --to-destination IP:起-止
to_dest_port(){
  local src="$1"
  if is_port_range "$src"; then
    echo "${src}"   # 直接用 2333-6666
  else
    echo "${src}"
  fi
}

# 幂等添加：存在就不重复加
iptables_add_once(){
  local table="$1"; shift
  local chain="$1"; shift
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    echo -e "${Tip} 规则已存在，跳过: iptables -t $table -A $chain $*"
  else
    iptables -t "$table" -A "$chain" "$@"
  fi
}

iptables_del_if_exists(){
  local table="$1"; shift
  local chain="$1"; shift
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    iptables -t "$table" -D "$chain" "$@"
  fi
}

Add_iptables_rule(){
  local proto="$1"

  # DNAT: PREROUTING
  iptables_add_once nat PREROUTING -p "$proto" --dport "${local_port}" \
    -j DNAT --to-destination "${forwarding_ip}:$(to_dest_port "${forwarding_port}")"

  # SNAT/MASQUERADE: 推荐 MASQUERADE（多IP/动态更稳），但保留固定SNAT逻辑
  # 这里用 SNAT（与你原脚本一致），如果你希望更稳可改成 MASQUERADE
  iptables_add_once nat POSTROUTING -p "$proto" -d "${forwarding_ip}" --dport "${forwarding_port}" \
    -j SNAT --to-source "${local_ip}"

  # 放行转发流量（关键）
  iptables_add_once filter FORWARD -p "$proto" -d "${forwarding_ip}" --dport "${forwarding_port}" -j ACCEPT

  echo -e "${Info} 已添加: ${proto} ${local_port} -> ${forwarding_ip}:${forwarding_port}"
}

Add_forwarding(){
  need_root
  check_iptables
  set_ip_forward
  Set_Config

  if [[ "${forwarding_type}" == "TCP" ]]; then
    Add_iptables_rule "tcp"
  elif [[ "${forwarding_type}" == "UDP" ]]; then
    Add_iptables_rule "udp"
  else
    Add_iptables_rule "tcp"
    Add_iptables_rule "udp"
  fi

  Save_iptables
  echo -e "${Info} 保存完成！"
}

# 只显示我们关心的DNAT规则
View_forwarding(){
  check_iptables
  echo -e "${Info} 当前 PREROUTING(DNAT) 规则："
  iptables -t nat -S PREROUTING | grep -E -- '-j DNAT' || echo -e "${Tip} 暂无DNAT规则"
}

# 交互删除：按你输入的“本地端口+远程IP+远程端口+协议”精准删除，避免删错
Del_forwarding(){
  need_root
  check_iptables

  # 取出DNAT规则列表（只取 PREROUTING 中的 DNAT）
  mapfile -t rules < <(iptables -t nat -S PREROUTING | grep -E -- '-j DNAT')

  if [[ ${#rules[@]} -eq 0 ]]; then
    echo -e "${Error} 没有发现 DNAT 转发规则！"
    return
  fi

  echo -e "\n${Info} 当前 DNAT 转发规则列表："
  echo "————————————————————————————————————"

  # 输出编号列表
  for i in "${!rules[@]}"; do
    idx=$((i+1))
    proto=$(echo "${rules[$i]}" | awk '{for(j=1;j<=NF;j++) if($j=="-p") print $(j+1)}')
    lport=$(echo "${rules[$i]}" | awk -F'--dport ' '{print $2}' | awk '{print $1}')
    dest=$(echo "${rules[$i]}" | awk -F'--to-destination ' '{print $2}')
    echo -e "${Green}${idx}.${NC} 协议:${Red}${proto}${NC} 本地端口:${Red}${lport}${NC} -> 目标:${Red}${dest}${NC}"
  done

  echo "————————————————————————————————————"
  read -r -e -p "请输入要删除的规则编号(回车取消): " num

  [[ -z "${num}" ]] && echo "取消..." && return

  # 检查输入合法
  if ! [[ "${num}" =~ ^[0-9]+$ ]]; then
    echo -e "${Error} 输入必须是数字！"
    return
  fi

  if (( num < 1 || num > ${#rules[@]} )); then
    echo -e "${Error} 编号超出范围！"
    return
  fi

  target_rule="${rules[$((num-1))]}"

  # 从规则里解析参数
  proto=$(echo "${target_rule}" | awk '{for(j=1;j<=NF;j++) if($j=="-p") print $(j+1)}')
  lport=$(echo "${target_rule}" | awk -F'--dport ' '{print $2}' | awk '{print $1}')
  dest=$(echo "${target_rule}" | awk -F'--to-destination ' '{print $2}')

  forwarding_ip="${dest%%:*}"
  forwarding_port="${dest#*:}"

  echo -e "${Tip} 正在删除：${proto} ${lport} -> ${forwarding_ip}:${forwarding_port}"

  # 删除 DNAT（PREROUTING）
  iptables -t nat -D PREROUTING -p "${proto}" --dport "${lport}" -j DNAT --to-destination "${forwarding_ip}:${forwarding_port}"

  # 删除 SNAT（POSTROUTING）如果存在
  iptables -t nat -D POSTROUTING -p "${proto}" -d "${forwarding_ip}" --dport "${forwarding_port}" -j SNAT --to-source "$(detect_local_ip)" 2>/dev/null || true

  # 删除 FORWARD 放行（如果存在）
  iptables -D FORWARD -p "${proto}" -d "${forwarding_ip}" --dport "${forwarding_port}" -j ACCEPT 2>/dev/null || true

  Save_iptables
  echo -e "${Info} 删除完成并已保存！"
}

Uninstall_forwarding(){
  need_root
  check_iptables
  echo -e "${RedBg}警告${NC}：将清空所有 DNAT 端口转发规则（PREROUTING中的DNAT）。"
  read -r -e -p "确认清空？[y/N]: " yn
  [[ -z "$yn" ]] && yn="n"
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "取消..."; return; }

  # 只删 DNAT 相关，不碰你其他 NAT 规则（相对安全）
  while read -r rule; do
    # rule 形如：-A PREROUTING ... -j DNAT --to-destination x:x
    iptables -t nat ${rule/-A/-D}
  done < <(iptables -t nat -S PREROUTING | grep -E -- '-j DNAT' || true)

  Save_iptables
  echo -e "${Info} 已清空DNAT转发规则并保存！"
}

Save_iptables(){
  if [[ ${release} == "centos" ]]; then
    if systemctl list-unit-files | grep -q '^iptables\.service'; then
      systemctl enable iptables >/dev/null 2>&1 || true
      systemctl restart iptables >/dev/null 2>&1 || true
    fi
    service iptables save >/dev/null 2>&1 || true
  else
    # 优先用 iptables-persistent
    if dpkg -s iptables-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    else
      iptables-save > /etc/iptables.up.rules
      if [[ -d /etc/network/if-pre-up.d ]]; then
        cat > /etc/network/if-pre-up.d/iptables <<'EOF'
#!/bin/bash
/sbin/iptables-restore < /etc/iptables.up.rules
EOF
        chmod +x /etc/network/if-pre-up.d/iptables
      fi
    fi
  fi
}

persist_iptables_hint(){
  if [[ ${release} != "centos" ]]; then
    if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
      echo -e "${Tip} 建议安装持久化：apt-get install -y iptables-persistent"
    fi
  fi
}

Update_Shell(){
  echo -e "${Tip} 该优化版不提供在线覆盖更新（避免安全风险）。"
}

main_menu(){
  echo -e "\n iptables 端口转发一键管理脚本 ${Red}[v${sh_ver}]${NC}
————————————
 ${Green}1.${NC} 安装/初始化 iptables(含开启转发/持久化)
 ${Green}2.${NC} 清空 DNAT 端口转发(更安全：只清DNAT)
————————————
 ${Green}3.${NC} 查看 DNAT 端口转发
 ${Green}4.${NC} 添加端口转发
 ${Green}5.${NC} 删除指定端口转发(按参数精准删)
————————————\n"
  read -r -e -p "请输入数字 [1-5]:" num
  case "$num" in
    1) install_iptables ;;
    2) Uninstall_forwarding ;;
    3) View_forwarding ;;
    4) Add_forwarding ;;
    5) Del_forwarding ;;
    *) echo "请输入正确数字 [1-5]" ;;
  esac
}

need_root
check_sys
main_menu
