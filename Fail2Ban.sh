#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\n==> $*"; }
warn() { echo -e "\n[WARN] $*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 权限运行：sudo bash $0"
  exit 1
fi

if [[ ! -f /etc/debian_version ]] || ! command -v systemctl >/dev/null 2>&1; then
  echo "仅支持使用 systemd 的 Debian/Ubuntu"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

log "安装 Fail2Ban、UFW 和必要依赖..."
apt-get update -y
apt-get install -y fail2ban ufw iptables iproute2

detect_ssh_ports() {
  local ports=""

  # 优先读取 sshd 当前实际监听的端口，可正确处理多个 Port 配置。
  if command -v ss >/dev/null 2>&1; then
    ports="$(
      ss -H -ltnp 2>/dev/null |
        awk '/sshd/ {print $4}' |
        sed -nE 's/.*:([0-9]+)$/\1/p' |
        sort -nu |
        paste -sd, - || true
    )"
  fi

  # sshd 尚未启动时，从展开 Include 后的有效配置读取。
  if [[ -z "$ports" ]] && command -v sshd >/dev/null 2>&1; then
    ports="$(
      sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null |
        awk '$1 == "port" && $2 ~ /^[0-9]+$/ {print $2}' |
        sort -nu |
        paste -sd, - || true
    )"
  fi

  echo "${ports:-22}"
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
}

SSH_PORTS="$(detect_ssh_ports)"
IFS=',' read -r -a SSH_PORT_LIST <<< "$SSH_PORTS"

for port in "${SSH_PORT_LIST[@]}"; do
  if ! validate_port "$port"; then
    echo "检测到无效的 SSH 端口：$port"
    exit 1
  fi
done

log "检测到 SSH 端口：${SSH_PORTS}"
log "配置 UFW，放行 SSH、HTTP 和 HTTPS..."

# 必须先放行 SSH，再启用防火墙，避免中断当前远程连接。
for port in "${SSH_PORT_LIST[@]}"; do
  ufw allow "${port}/tcp"
done
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

install -d -m 0755 /etc/fail2ban/jail.d
PROD_FILE="/etc/fail2ban/jail.d/00-production.local"
BACKUP_FILE=""

if [[ -f "$PROD_FILE" ]]; then
  BACKUP_FILE="${PROD_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
  log "备份已有配置到：${BACKUP_FILE}"
  cp -a "$PROD_FILE" "$BACKUP_FILE"
fi

log "写入 Fail2Ban 配置..."
cat > "$PROD_FILE" <<EOF
[DEFAULT]
# 仅忽略本机地址，避免把经 NAT 访问的外部客户端意外加入白名单。
ignoreip = 127.0.0.1/8 ::1

# Debian/Ubuntu 使用 systemd journal，不再同时指定 logpath。
backend = systemd

# 相比永久封禁更宽松：10 分钟内失败 5 次，封禁 1 小时。
findtime = 10m
maxretry = 5
bantime = 1h

# iptables-multiport 会根据来源地址自动处理 IPv4 或 IPv6。
banaction = iptables-multiport

[sshd]
enabled = true
port = ${SSH_PORTS}
EOF

log "检查 Fail2Ban 配置..."
if ! fail2ban-client -t; then
  warn "配置检查失败，正在恢复原配置"
  if [[ -n "$BACKUP_FILE" ]]; then
    cp -a "$BACKUP_FILE" "$PROD_FILE"
  else
    rm -f "$PROD_FILE"
  fi
  exit 1
fi

log "启用并重启 Fail2Ban..."
systemctl enable fail2ban
systemctl restart fail2ban

FAIL2BAN_STATUS=""
SSHD_JAIL_STATUS=""

wait_for_fail2ban() {
  local attempt

  for attempt in {1..15}; do
    if FAIL2BAN_STATUS="$(fail2ban-client status 2>/dev/null)" &&
      SSHD_JAIL_STATUS="$(fail2ban-client status sshd 2>/dev/null)"; then
      return 0
    fi

    if systemctl is-failed --quiet fail2ban; then
      return 1
    fi

    sleep 1
  done

  return 1
}

if ! wait_for_fail2ban; then
  warn "Fail2Ban 未能在 15 秒内就绪"
  systemctl --no-pager --full status fail2ban || true
  journalctl --no-pager -u fail2ban -n 50 || true
  exit 1
fi

log "Fail2Ban 状态："
printf '%s\n' "$FAIL2BAN_STATUS"
printf '%s\n' "$SSHD_JAIL_STATUS"

log "UFW 状态："
ufw status verbose

log "安装完成：Fail2Ban 已启用；UFW 已放行 SSH(${SSH_PORTS})、80 和 443/tcp"
echo "手动封禁：fail2ban-client set sshd banip 8.8.8.8"
echo "手动解封：fail2ban-client set sshd unbanip 8.8.8.8"
