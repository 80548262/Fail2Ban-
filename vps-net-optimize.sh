#!/usr/bin/env bash

# ==========================================================
# Adaptive VPS network optimization
# BBR + TCP + Docker/NAT + Nginx
# Ubuntu 22.04 / 24.04
# ==========================================================

set -Eeuo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-vps-network.conf"
LIMITS_FILE="/etc/security/limits.d/99-nofile.conf"
MODULES_FILE="/etc/modules-load.d/bbr.conf"
BACKUP_ROOT="/root/sysctl-backup"
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: vps-net-optimize.sh [--dry-run] [--help]

  --dry-run  Detect hardware and print the generated sysctl config only.
  --help     Show this help message.
EOF
}

log() {
    printf '%s\n' "$*"
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

is_positive_integer() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

min_value() {
    if (( $1 < $2 )); then
        printf '%s\n' "$1"
    else
        printf '%s\n' "$2"
    fi
}

max_value() {
    if (( $1 > $2 )); then
        printf '%s\n' "$1"
    else
        printf '%s\n' "$2"
    fi
}

clamp_value() {
    local minimum="$1"
    local value="$2"
    local maximum="$3"

    if (( value < minimum )); then
        printf '%s\n' "$minimum"
    elif (( value > maximum )); then
        printf '%s\n' "$maximum"
    else
        printf '%s\n' "$value"
    fi
}

detect_cpu_cores() {
    local detected=""
    local quota=""
    local period=""
    local quota_cores=""

    if command -v nproc >/dev/null 2>&1; then
        detected=$(nproc 2>/dev/null || true)
    fi
    if ! is_positive_integer "$detected" && command -v getconf >/dev/null 2>&1; then
        detected=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    if ! is_positive_integer "$detected"; then
        detected=$(awk '/^processor[[:space:]]*:/ { count++ } END { print count + 0 }' /proc/cpuinfo 2>/dev/null || true)
    fi
    is_positive_integer "$detected" || die "Unable to detect available CPU cores."

    # Respect cgroup v2 CPU quotas when nproc only reports host CPUs.
    if [[ -r /sys/fs/cgroup/cpu.max ]] && read -r quota period < /sys/fs/cgroup/cpu.max; then
        if [[ "$quota" != "max" ]] && is_positive_integer "$quota" && is_positive_integer "$period"; then
            quota_cores=$(( (quota + period - 1) / period ))
        fi
    elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us && -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]]; then
        quota=$(< /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(< /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        if is_positive_integer "$quota" && is_positive_integer "$period"; then
            quota_cores=$(( (quota + period - 1) / period ))
        fi
    fi

    if is_positive_integer "$quota_cores" && (( quota_cores < detected )); then
        detected="$quota_cores"
    fi

    printf '%s\n' "$detected"
}

detect_memory_mb() {
    local detected_kb=""
    local detected_mb=""
    local limit_bytes=""
    local limit_mb=""

    detected_kb=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)
    is_positive_integer "$detected_kb" || die "Unable to detect available memory."
    detected_mb=$(( detected_kb / 1024 ))

    if [[ -r /sys/fs/cgroup/memory.max ]]; then
        limit_bytes=$(< /sys/fs/cgroup/memory.max)
    elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
        limit_bytes=$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)
    fi

    if is_positive_integer "$limit_bytes"; then
        limit_mb=$(( limit_bytes / 1024 / 1024 ))
        if (( limit_mb > 0 && limit_mb < detected_mb )); then
            detected_mb="$limit_mb"
        fi
    fi

    (( detected_mb > 0 )) || detected_mb=1
    printf '%s\n' "$detected_mb"
}

detect_page_size_kb() {
    local page_size=""

    if command -v getconf >/dev/null 2>&1; then
        page_size=$(getconf PAGESIZE 2>/dev/null || true)
    fi
    if ! is_positive_integer "$page_size"; then
        page_size=4096
    fi

    printf '%s\n' "$(( page_size / 1024 ))"
}

calculate_tuning() {
    local memory_queue_cap=""
    local memory_backlog_cap=""
    local conntrack_by_memory=""
    local conntrack_by_cpu=""
    local tcp_mem_min_pages=""
    local tcp_mem_max_pages=""
    local total_memory_pages=""
    local current_file_max=""
    local current_nr_open=""

    if (( MEMORY_MB <= 1024 )); then
        MEMORY_PROFILE="memory-constrained"
    elif (( MEMORY_MB <= 4096 )); then
        MEMORY_PROFILE="balanced"
    elif (( MEMORY_MB <= 16384 )); then
        MEMORY_PROFILE="high-throughput"
    else
        MEMORY_PROFILE="large-memory"
    fi

    if (( MEMORY_MB <= 1024 )); then
        SOCKET_BUFFER_MAX=4194304
        TCP_BUFFER_DEFAULT=65536
        SWAPPINESS=20
    elif (( MEMORY_MB <= 2048 )); then
        SOCKET_BUFFER_MAX=8388608
        TCP_BUFFER_DEFAULT=131072
        SWAPPINESS=10
    elif (( MEMORY_MB <= 4096 )); then
        SOCKET_BUFFER_MAX=16777216
        TCP_BUFFER_DEFAULT=262144
        SWAPPINESS=5
    elif (( MEMORY_MB <= 8192 )); then
        SOCKET_BUFFER_MAX=33554432
        TCP_BUFFER_DEFAULT=262144
        SWAPPINESS=1
    else
        SOCKET_BUFFER_MAX=67108864
        TCP_BUFFER_DEFAULT=262144
        SWAPPINESS=1
    fi

    memory_queue_cap=$(clamp_value 4096 "$(( MEMORY_MB * 8 ))" 65535)
    SOMAXCONN=$(clamp_value 4096 "$(( CPU_CORES * 4096 ))" 65535)
    SOMAXCONN=$(min_value "$SOMAXCONN" "$memory_queue_cap")

    memory_backlog_cap=$(clamp_value 4096 "$(( MEMORY_MB * 16 ))" 65536)
    NETDEV_MAX_BACKLOG=$(clamp_value 4096 "$(( CPU_CORES * 8192 ))" 65536)
    NETDEV_MAX_BACKLOG=$(min_value "$NETDEV_MAX_BACKLOG" "$memory_backlog_cap")

    if (( MEMORY_MB <= 512 )); then
        TCP_MAX_TW_BUCKETS=16384
        NOFILE_LIMIT=65536
    elif (( MEMORY_MB <= 1024 )); then
        TCP_MAX_TW_BUCKETS=32768
        NOFILE_LIMIT=131072
    elif (( MEMORY_MB <= 2048 )); then
        TCP_MAX_TW_BUCKETS=65536
        NOFILE_LIMIT=262144
    elif (( MEMORY_MB <= 4096 )); then
        TCP_MAX_TW_BUCKETS=65536
        NOFILE_LIMIT=524288
    elif (( MEMORY_MB <= 8192 )); then
        TCP_MAX_TW_BUCKETS=131072
        NOFILE_LIMIT=1048576
    else
        TCP_MAX_TW_BUCKETS=262144
        NOFILE_LIMIT=1048576
    fi

    conntrack_by_memory=$(( MEMORY_MB * 96 ))
    conntrack_by_cpu=$(( CPU_CORES * 131072 ))
    CONNTRACK_MAX=$(min_value "$conntrack_by_memory" "$conntrack_by_cpu")
    CONNTRACK_MAX=$(clamp_value 32768 "$CONNTRACK_MAX" 1048576)

    FILE_MAX=$(clamp_value 131072 "$(( NOFILE_LIMIT * 2 ))" 2097152)
    if [[ -r /proc/sys/fs/file-max ]]; then
        current_file_max=$(< /proc/sys/fs/file-max)
        if is_positive_integer "$current_file_max"; then
            FILE_MAX=$(max_value "$FILE_MAX" "$current_file_max")
        fi
    fi
    NR_OPEN="$NOFILE_LIMIT"
    if [[ -r /proc/sys/fs/nr_open ]]; then
        current_nr_open=$(< /proc/sys/fs/nr_open)
        if is_positive_integer "$current_nr_open"; then
            NR_OPEN=$(max_value "$NR_OPEN" "$current_nr_open")
        fi
    fi

    # tcp_mem values are memory pages, not bytes. Keep its high watermark near
    # 12.5% of available memory, bounded to 8 MiB..8 GiB across page sizes.
    total_memory_pages=$(( MEMORY_MB * 1024 / PAGE_SIZE_KB ))
    tcp_mem_min_pages=$(( 8192 / PAGE_SIZE_KB ))
    tcp_mem_max_pages=$(( 8388608 / PAGE_SIZE_KB ))
    TCP_MEM_HIGH=$(clamp_value "$tcp_mem_min_pages" "$(( total_memory_pages / 8 ))" "$tcp_mem_max_pages")
    TCP_MEM_LOW=$(( TCP_MEM_HIGH / 2 ))
    TCP_MEM_PRESSURE=$(( TCP_MEM_HIGH * 3 / 4 ))
}

render_sysctl() {
    cat <<EOF
# Generated by vps-net-optimize.sh
# Detected profile: ${CPU_CORES} CPU(s), ${MEMORY_MB} MiB RAM, ${MEMORY_PROFILE}

# Memory
vm.swappiness = ${SWAPPINESS}
vm.overcommit_memory = 1
vm.max_map_count = 262144

# File handles
fs.file-max = ${FILE_MAX}
fs.nr_open = ${NR_OPEN}

# Network queues (scaled primarily by available CPU)
net.core.netdev_max_backlog = ${NETDEV_MAX_BACKLOG}
net.core.somaxconn = ${SOMAXCONN}

# Socket buffers (scaled by available memory)
net.core.rmem_max = ${SOCKET_BUFFER_MAX}
net.core.wmem_max = ${SOCKET_BUFFER_MAX}

# TCP memory, in memory pages
net.ipv4.tcp_mem = ${TCP_MEM_LOW} ${TCP_MEM_PRESSURE} ${TCP_MEM_HIGH}

# TCP windows
net.ipv4.tcp_rmem = 4096 ${TCP_BUFFER_DEFAULT} ${SOCKET_BUFFER_MAX}
net.ipv4.tcp_wmem = 4096 ${TCP_BUFFER_DEFAULT} ${SOCKET_BUFFER_MAX}

# BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP behavior
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_max_syn_backlog = ${SOMAXCONN}
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = ${TCP_MAX_TW_BUCKETS}

# Forwarding / NAT
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Reverse path filtering; loose mode supports asymmetric and container traffic
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Conntrack
net.netfilter.nf_conntrack_max = ${CONNTRACK_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
EOF
}

render_limits() {
    cat <<EOF
* soft nofile ${NOFILE_LIMIT}
* hard nofile ${NOFILE_LIMIT}
root soft nofile ${NOFILE_LIMIT}
root hard nofile ${NOFILE_LIMIT}
EOF
}

print_profile() {
    cat <<EOF
Detected resources:
  CPU cores:             ${CPU_CORES}
  Memory:                ${MEMORY_MB} MiB
  Profile:               ${MEMORY_PROFILE}
  Socket buffer maximum: ${SOCKET_BUFFER_MAX} bytes
  Network backlog:       ${NETDEV_MAX_BACKLOG}
  Listen/SYN backlog:    ${SOMAXCONN}
  Conntrack maximum:     ${CONNTRACK_MAX}
  Per-process nofile:    ${NOFILE_LIMIT}
EOF
}

backup_file() {
    local source="$1"
    local backup_dir="$2"

    if [[ -e "$source" ]]; then
        cp -a -- "$source" "$backup_dir/$(basename "$source")"
    fi
}

while (( $# > 0 )); do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Unknown option: $1"
            ;;
    esac
    shift
done

[[ "$(uname -s)" == "Linux" ]] || die "This script only supports Linux."

CPU_CORES=$(detect_cpu_cores)
MEMORY_MB=$(detect_memory_mb)
PAGE_SIZE_KB=$(detect_page_size_kb)
(( PAGE_SIZE_KB > 0 )) || die "Invalid system page size."
calculate_tuning

log "======================================"
log " Adaptive VPS Network Optimization"
log "======================================"
print_profile

if (( DRY_RUN == 1 )); then
    log ""
    log "Generated sysctl configuration:"
    log "--------------------------------------"
    render_sysctl
    exit 0
fi

(( EUID == 0 )) || die "Please run as root (or use --dry-run)."
command -v sysctl >/dev/null 2>&1 || die "sysctl is required."
command -v modprobe >/dev/null 2>&1 || die "modprobe is required."

log "[1/6] Loading kernel modules..."
modprobe tcp_bbr 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true

available_congestion=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
case " $available_congestion " in
    *" bbr "*) ;;
    *) die "BBR is unavailable in the current kernel." ;;
esac
[[ -e /proc/sys/net/netfilter/nf_conntrack_max ]] || die "nf_conntrack is unavailable in the current kernel."

timestamp=$(date +%F-%H%M%S)
backup_dir="${BACKUP_ROOT}/${timestamp}"
log "[2/6] Backing up managed configuration to ${backup_dir}..."
mkdir -p -- "$backup_dir"
backup_file /etc/sysctl.conf "$backup_dir"
backup_file "$SYSCTL_FILE" "$backup_dir"
backup_file "$LIMITS_FILE" "$backup_dir"
backup_file "$MODULES_FILE" "$backup_dir"

log "[3/6] Writing adaptive configuration..."
sysctl_tmp=""
limits_tmp=""
modules_tmp=""
cleanup() {
    rm -f -- "${sysctl_tmp:-}" "${limits_tmp:-}" "${modules_tmp:-}"
}
trap cleanup EXIT
sysctl_tmp=$(mktemp "${SYSCTL_FILE}.tmp.XXXXXX")
limits_tmp=$(mktemp "${LIMITS_FILE}.tmp.XXXXXX")
modules_tmp=$(mktemp "${MODULES_FILE}.tmp.XXXXXX")

render_sysctl > "$sysctl_tmp"
render_limits > "$limits_tmp"
printf 'tcp_bbr\n' > "$modules_tmp"
chmod 0644 "$sysctl_tmp" "$limits_tmp" "$modules_tmp"
mv -f -- "$sysctl_tmp" "$SYSCTL_FILE"
mv -f -- "$limits_tmp" "$LIMITS_FILE"
mv -f -- "$modules_tmp" "$MODULES_FILE"

log "[4/6] Applying managed sysctl configuration..."
sysctl -p "$SYSCTL_FILE" >/dev/null

log "[5/6] Verifying active settings..."
active_congestion=$(sysctl -n net.ipv4.tcp_congestion_control)
active_qdisc=$(sysctl -n net.core.default_qdisc)
active_conntrack=$(sysctl -n net.netfilter.nf_conntrack_max)

[[ "$active_congestion" == "bbr" ]] || die "BBR was configured but is not active."
[[ "$active_qdisc" == "fq" ]] || die "fq was configured but is not active."
[[ "$active_conntrack" == "$CONNTRACK_MAX" ]] || die "Conntrack limit was not applied."

log "[6/6] Completed."
log ""
log "Active settings:"
log "  TCP congestion control: ${active_congestion}"
log "  Default queue:          ${active_qdisc}"
log "  Conntrack maximum:      ${active_conntrack}"
log "  Backup:                 ${backup_dir}"
log ""
log "Reboot the VPS so module and service limits are applied consistently."
