#!/bin/bash

# ==========================================================
# 2C/3G VPS Network Optimization
# BBR + TCP + Docker + Nginx optimized
# Ubuntu 22.04 / 24.04
# ==========================================================

set -e

echo "======================================"
echo " VPS Network Optimization Starting..."
echo "======================================"

# root check
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi


SYSCTL_FILE="/etc/sysctl.d/99-vps-network.conf"


# backup
echo "[1/6] Backup sysctl..."

mkdir -p /root/sysctl-backup

cp -a /etc/sysctl.conf \
/root/sysctl-backup/sysctl.conf.$(date +%F-%H%M) 2>/dev/null || true


# write config

echo "[2/6] Writing sysctl config..."

cat > ${SYSCTL_FILE} <<EOF

# ==============================
# Memory
# ==============================

vm.swappiness = 1
vm.overcommit_memory = 1
vm.max_map_count = 262144


# ==============================
# File handles
# ==============================

fs.file-max = 524288
fs.nr_open = 524288


# ==============================
# Network queue
# ==============================

net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192


# ==============================
# Socket buffer
# ==============================

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216


# ==============================
# TCP memory
# ==============================

net.ipv4.tcp_mem = 65536 98304 131072


# ==============================
# TCP window
# ==============================

net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216


# ==============================
# BBR
# ==============================

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr


# ==============================
# TCP Optimization
# ==============================

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0

net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1

net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1

net.ipv4.tcp_max_tw_buckets = 65536


# ==============================
# Forward / NAT
# ==============================

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1


# ==============================
# Reverse path filter
# ==============================

net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2


# ==============================
# Conntrack
# ==============================

net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 1800


EOF


# apply

echo "[3/6] Applying sysctl..."

sysctl --system >/dev/null


# limits

echo "[4/6] Configure file limits..."

cat > /etc/security/limits.d/99-nofile.conf <<EOF

* soft nofile 524288
* hard nofile 524288
root soft nofile 524288
root hard nofile 524288

EOF


# enable bbr module

echo "[5/6] Enable BBR..."

cat >/etc/modules-load.d/bbr.conf <<EOF
tcp_bbr
EOF

modprobe tcp_bbr 2>/dev/null || true


# verify

echo "[6/6] Checking..."

echo
echo "------ TCP Congestion ------"
sysctl net.ipv4.tcp_congestion_control

echo
echo "------ Queue ------"
sysctl net.core.default_qdisc

echo
echo "------ Conntrack ------"
sysctl net.netfilter.nf_conntrack_max


echo
echo "======================================"
echo " Optimization completed!"
echo " Please reboot VPS."
echo "======================================"
