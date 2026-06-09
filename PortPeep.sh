#!/usr/bin/bash
# POSIX Network Monitor – Exact behavioral port of Python version
# No non-standard dependencies
LOG_FILE="/var/log/network_monitor.log"
LOG_MAX_BYTES=5242880
LOG_BACKUPS=5
RATE_LIMIT_SECONDS=60
DISK_SPACE_THRESHOLD_KB=1048576   # 1GB
STATE_DIR="/tmp/network_monitor_state"
ALLOWED_PORTS="22 53 80 443"
# Allowed IPv4 CIDRs (exact Python equivalent)
ALLOWED_IPV4_CIDRS="127.0.0.0/8 192.168.1.0/24"
ALLOW_IPV6_LOOPBACK=1
run_user_access_audit() {
echo "========================================="
echo " Linux User & Access Audit"
echo " Timestamp: $(date)"
echo "========================================="
echo
echo "========== Hostname =========="
hostnamectl 2>/dev/null || hostname
echo
echo "========== Normal user accounts (UID >= 1000) =========="
awk -F: '$3 >= 1000 && $3 < 65534 {printf "%-20s UID=%s\n",$1,$3}' /etc/passwd
echo
echo "========== Sudo group members =========="
getent group sudo
echo
echo "========== Wheel group members =========="
getent group wheel
echo
echo "========== Currently logged in users =========="
who
echo
echo "========== Active sessions =========="
loginctl list-sessions 2>/dev/null
echo
echo "========== All currently logged in users =========="
users | tr ' ' '\n' | sort -u
echo
echo "========== Last 20 logins =========="
last -a | head -20
echo
echo "========== Last login for each user =========="
lastlog
echo
echo "========== Failed login attempts (lastb) =========="
if [ -f /var/log/btmp ]; then
    sudo lastb | head -20
else
    echo "No /var/log/btmp file found."
fi
echo
echo "========== Recent sudo activity =========="
if [ -f /var/log/auth.log ]; then
    sudo grep -i sudo /var/log/auth.log | tail -20
else
    journalctl -u sudo --no-pager -n 20 2>/dev/null
fi
echo
echo "========== Passwordless sudo rules =========="
sudo grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo "None found"
echo
echo "========== SSH authorized keys =========="
find /home -name authorized_keys -exec ls -l {} \; 2>/dev/null || echo "No authorized_keys found"
echo
echo "========== Running user sessions =========="
ps -eo user,pid,ppid,cmd --sort=user | grep -E "(cinnamon|gnome|xfce|kde|mate|lightdm|sddm|gdm)" | grep -v grep
echo
echo "========== Listening network ports =========="
ss -tulpn
echo
echo "========== Top memory consumers =========="
ps aux --sort=-%mem | head -15
echo
echo "========== Top CPU consumers =========="
ps aux --sort=-%cpu | head -15
echo
echo "========== Accounts with login shells =========="
grep -vE '(/false|/nologin)$' /etc/passwd
echo
echo "========== Running services =========="
systemctl --type=service --state=running
echo
echo "========================================="
echo " Audit Complete"
echo " Timestamp: $(date)"
echo "========================================="
}
mkdir -p "$STATE_DIR" || exit 1
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}
rotate_logs() {
    [ -f "$LOG_FILE" ] || return
    size=$(wc -c < "$LOG_FILE")
    [ "$size" -lt "$LOG_MAX_BYTES" ] && return
    i=$LOG_BACKUPS
    while [ $i -gt 1 ]; do
        prev=$((i - 1))
        [ -f "$LOG_FILE.$prev" ] && mv "$LOG_FILE.$prev" "$LOG_FILE.$i"
        i=$prev
    done
    mv "$LOG_FILE" "$LOG_FILE.1"
}
log() {
    level="$1"
    msg="$2"
    rotate_logs
    touch "$LOG_FILE" 2>/dev/null || \
        die "Cannot write to log file."
    printf "%s - %s - %s\n" "$(timestamp)" "$level" "$msg" >> "$LOG_FILE"
    [ "$TERMINAL_OUTPUT" = "1" ] && \
        printf "%s - %s\n" "$level" "$msg"
}
die() {
    log "ERROR" "$1"
    exit 1
}
check_root() {
    [ "$(id -u)" -ne 0 ] && die "Must be run as root."
}
check_disk_space() {
    target=$(dirname "$LOG_FILE")
    free_kb=$(df -Pk "$target" | awk 'NR==2 {print $4}')
    [ -z "$free_kb" ] && die "Unable to determine free disk space."
    [ "$free_kb" -lt "$DISK_SPACE_THRESHOLD_KB" ] && \
        die "Disk space is low! Stopping the script."
}
rate_limited() {
    key="$1"
    now=$(date +%s)
    file="$STATE_DIR/$key"
    if [ -f "$file" ]; then
        last=$(cat "$file")
        [ $((now - last)) -lt "$RATE_LIMIT_SECONDS" ] && return 0
    fi
    echo "$now" > "$file"
    return 1
}
is_allowed_port() {
    for p in $ALLOWED_PORTS; do
        [ "$p" = "$1" ] && return 0
    done
    return 1
}
ipv4_in_cidr() {
    ip="$1"
    cidr="$2"
    net=$(echo "$cidr" | cut -d/ -f1)
    maskbits=$(echo "$cidr" | cut -d/ -f2)
    ip_dec=$(echo "$ip" | awk -F. '{print ($1*16777216)+($2*65536)+($3*256)+$4}')
    net_dec=$(echo "$net" | awk -F. '{print ($1*16777216)+($2*65536)+($3*256)+$4}')
    mask=$((0xFFFFFFFF << (32 - maskbits) & 0xFFFFFFFF))
    [ $((ip_dec & mask)) -eq $((net_dec & mask)) ]
}
is_allowed_ip() {
    ip="$1"
    [ "$ip" = "::1" ] && [ "$ALLOW_IPV6_LOOPBACK" -eq 1 ] && return 0
    echo "$ip" | grep -q ':' && return 1
    for cidr in $ALLOWED_IPV4_CIDRS; do
        ipv4_in_cidr "$ip" "$cidr" && return 0
    done
    return 1
}
clean_ip() {
    echo "$1" | cut -d% -f1
}
process_connections() {
    ss -tun | awk 'NR>1 {print $1, $5}' | while read proto dest; do
        ip=$(clean_ip "$(echo "$dest" | cut -d: -f1)")
        port=$(echo "$dest" | awk -F: '{print $NF}')
        echo "$port" | grep -q '^[0-9]\+$' || continue
        [ "$ip" = "127.0.0.1" ] || [ "$ip" = "::1" ] && continue
        key="conn_${ip}_${port}_${proto}"
        if ! is_allowed_port "$port" && ! is_allowed_ip "$ip"; then
            rate_limited "$key" && continue
            log "WARN" "[ALERT] Unusual outbound connection"
            log "WARN" "Protocol: $proto"
            log "WARN" "Destination: $ip:$port"
        else
            log "INFO" "[OK] $proto -> $ip:$port"
        fi
    done
}
process_processes() {
    ss -tunp | while read line; do
        echo "$line" | grep -q pid= || continue
        dest=$(echo "$line" | awk '{print $5}')
        port=$(echo "$dest" | awk -F: '{print $NF}')
        echo "$port" | grep -q '^[0-9]\+$' || continue
        pid=$(echo "$line" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
        [ -z "$pid" ] && continue
        is_allowed_port "$port" && continue
        key="proc_${pid}_${port}"
        rate_limited "$key" && continue
        name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        log "WARN" "[ALERT] Process using non-standard port (note: ALERT does not mean a compromise it just means it triggered something(always investigate manually before assuming the worst)"
        log "WARN" "Process: $name (PID $pid)"
        log "WARN" "Port: $port"
    done
}
run_once() {
    check_disk_space
    process_connections
    process_processes
    run_user_access_audit >> "$LOG_FILE" 2>&1
    echo "User access audit written to $LOG_FILE"
}
usage() {
    echo "Usage:"
    echo "  $0 --continuous"
    echo "  $0 --one-time"
    echo "  $0 --terminal"
}
check_root
CONTINUOUS=0
TERMINAL_OUTPUT=0
[ $# -eq 0 ] && usage && exit 0
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--continuous) CONTINUOUS=1 ;;
        -o|--one-time) CONTINUOUS=0 ;;
        --terminal) TERMINAL_OUTPUT=1 ;;
        *) usage; exit 1 ;;
    esac
    shift
done
log "INFO" "Network monitor started"
if [ "$CONTINUOUS" -eq 1 ]; then
    while :; do
        run_once
        sleep 10
    done
else
    run_once
    log "INFO" "One-time network scan completed"
fi
