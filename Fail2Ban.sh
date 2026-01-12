#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "\n==> $*"; }
warn(){ echo -e "\n[WARN] $*" >&2; }

# root check
if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo $0"
  exit 1
fi

# Debian/Ubuntu only
if [[ ! -f /etc/debian_version ]]; then
  echo "仅支持 Debian/Ubuntu（systemd）"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

log "安装/更新 fail2ban + ufw + iptables..."
apt-get update -y
apt-get install -y fail2ban ufw iptables curl

detect_ssh_port() {
  local p=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    # 取最后一个 Port（若配置多个）
    p="$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1 || true)"
  fi
  if [[ -z "${p:-}" ]] && command -v ss >/dev/null 2>&1; then
    p="$(ss -ltnp 2>/dev/null | awk '/sshd/ && /LISTEN/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | head -n 1 || true)"
  fi
  echo "${p:-22}"
}

get_public_ipv4() {
  local ip=""
  for url in "https://api.ipify.org" "https://ifconfig.me/ip"; do
    ip="$(curl -4 -fsS "$url" 2>/dev/null || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  echo ""
}

SSH_PORT="$(detect_ssh_port)"
PUB_IPv4="$(get_public_ipv4)"

log "检测 SSH 端口：${SSH_PORT}"
if [[ -n "$PUB_IPv4" ]]; then
  log "检测公网 IPv4（加入白名单）：${PUB_IPv4}"
else
  warn "未能获取公网 IPv4（不会自动加白名单）。你设置的是永久封禁，强烈建议手动补上 ignoreip！"
fi

log "配置 UFW 放行 SSH/80/443（不影响 Fail2Ban 封禁方式）..."
ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# 生产配置文件（覆盖旧的我们自己的文件，不碰 defaults-debian.conf）
mkdir -p /etc/fail2ban/jail.d
PROD_FILE="/etc/fail2ban/jail.d/00-production.local"

# 备份旧生产文件（如果存在）
if [[ -f "$PROD_FILE" ]]; then
  bk="${PROD_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
  log "备份旧配置到：$bk"
  cp -a "$PROD_FILE" "$bk"
fi

log "写入生产配置（IPv4+IPv6 双栈封禁：family=all + iptables-multiport）..."
cat > "$PROD_FILE" <<EOF
[DEFAULT]
# 白名单：本机 + 你的公网 IPv4（best-effort）
ignoreip = 127.0.0.1/8 ::1${PUB_IPv4:+ $PUB_IPv4}

# 使用 systemd 日志（Debian/Ubuntu 推荐）
backend = systemd

# 你的规则：60 秒失败 2 次 -> 永久封
findtime = 60
maxretry = 2
bantime  = -1

# 关键：同时对 IPv4 + IPv6 生效
family = all

# 关键：用 iptables/ip6tables 进行封禁（最稳，双栈不绕过）
banaction = iptables-multiport

[sshd]
enabled = true
port    = ${SSH_PORT}
logpath = /var/log/auth.log
EOF

log "启用并重启 Fail2Ban..."
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
sleep 1

log "运行状态："
systemctl --no-pager --full status fail2ban | sed -n '1,12p' || true

log "Jail 列表："
fail2ban-client status || true

log "sshd jail 状态："
fail2ban-client status sshd || true

log "验证双栈封禁链是否存在（iptables / ip6tables）..."
if command -v iptables >/dev/null 2>&1; then
  iptables -S | grep -i fail2ban >/dev/null 2>&1 && echo "OK: iptables 有 fail2ban 规则" || echo "WARN: iptables 未看到 fail2ban 规则（可再触发一次 ban）"
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -S | grep -i fail2ban >/dev/null 2>&1 && echo "OK: ip6tables 有 fail2ban 规则" || echo "WARN: ip6tables 未看到 fail2ban 规则（可再触发一次 ban）"
else
  warn "系统没有 ip6tables 命令（少见）。如果你确实启用了 IPv6，建议检查 iptables 包/替代实现。"
fi

log "完成 ✅（已自动修复旧安装配置，IPv4/IPv6 都封；UFW 已放行 SSH/80/443；Fail2Ban 已开机自启）"
echo "提示：可用这条命令快速测试 ban： fail2ban-client set sshd banip 8.8.8.8"
echo "解封： fail2ban-client set sshd unbanip 8.8.8.8"
