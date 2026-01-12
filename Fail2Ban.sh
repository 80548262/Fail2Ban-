#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "\n==> $*"; }
warn(){ echo -e "\n[WARN] $*" >&2; }

# 必须 root
if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo $0"
  exit 1
fi

# 仅 Debian / Ubuntu
if [[ ! -f /etc/debian_version ]]; then
  echo "仅支持 Debian / Ubuntu"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

log "安装 fail2ban / ufw / 依赖..."
apt-get update -y
apt-get install -y fail2ban ufw curl iptables

# 自动识别 SSH 端口
detect_ssh_port() {
  local p=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    p="$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1 || true)"
  fi
  if [[ -z "$p" ]] && command -v ss >/dev/null 2>&1; then
    p="$(ss -ltnp | awk '/sshd/ && /LISTEN/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | head -n 1 || true)"
  fi
  echo "${p:-22}"
}

# 获取公网 IP
get_public_ip() {
  for url in "https://api.ipify.org" "https://ifconfig.me/ip"; do
    ip="$(curl -4 -fsS "$url" 2>/dev/null || true)"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && echo "$ip" && return
  done
  echo ""
}

SSH_PORT="$(detect_ssh_port)"
PUB_IP="$(get_public_ip)"

log "SSH 端口：$SSH_PORT"
[[ -n "$PUB_IP" ]] && log "公网 IP（加入白名单）：$PUB_IP" || warn "未获取到公网 IP，请手动检查 ignoreip"

log "配置 UFW 放行必要端口（SSH / 80 / 443）..."
ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

log "写入 ufw-noinsert action（避免 insert 1 报错）..."
cat > /etc/fail2ban/action.d/ufw-noinsert.conf <<'EOF'
[Definition]
actionstart =
actionstop =
actioncheck = ufw status >/dev/null 2>&1
actionban   = ufw deny from <ip> to any port <port> proto <protocol>
actionunban = ufw --force delete deny from <ip> to any port <port> proto <protocol>
[Init]
protocol = tcp
EOF

BANACTION="ufw-noinsert"
command -v ufw >/dev/null 2>&1 || BANACTION="iptables-multiport"

log "写入 Fail2Ban 生产配置..."
mkdir -p /etc/fail2ban/jail.d

cat > /etc/fail2ban/jail.d/00-production.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1${PUB_IP:+ $PUB_IP}
backend  = systemd

# 60 秒失败 2 次 → 永久封
findtime = 60
maxretry = 2
bantime  = -1

banaction = ${BANACTION}

[sshd]
enabled = true
port    = ${SSH_PORT}
logpath = /var/log/auth.log
EOF

log "启用并重启 Fail2Ban..."
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
sleep 1

log "运行状态检查："
fail2ban-client status || true
fail2ban-client status sshd || true

log "完成 ✅"
log "SSH / 80 / 443 已放行，Fail2Ban 已启用并开机自启"
