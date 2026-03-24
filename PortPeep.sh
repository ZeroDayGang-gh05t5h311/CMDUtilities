#!/usr/bin/bash
RATE_LIMIT_SECONDS=60
BASELINE_FILE="baseline.json"
LOG_FILE="/var/log/network_monitor.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))  # 5 MB
DISK_USAGE_THRESHOLD=95  # 95% disk usage
ALLOWED_PORTS=(22 53 443 8080)
ALLOWED_IP_RANGES=("127.0.0.0/8" "192.168.1.0/24")
rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        LOG_SIZE=$(stat -c %s "$LOG_FILE")
        if [ "$LOG_SIZE" -ge "$MAX_LOG_SIZE" ]; then
            mv "$LOG_FILE" "$LOG_FILE.1"
        fi
    fi
}
log_msg() {
    local msg="$1"
    rotate_logs
    echo "$msg" >> "$LOG_FILE"
    echo "$msg"
}
check_disk_space() {
    # Get disk usage percentage
    local usage=$(df / --output=pcent | tail -n 1 | tr -d '%')
    if [ "$usage" -gt "$DISK_USAGE_THRESHOLD" ]; then
        log_msg "Disk usage is above $DISK_USAGE_THRESHOLD%. Terminating program."
        return 1
    fi
    return 0
}
load_config() {
    local config_file="$1"
    if [ -f "$config_file" ]; then
        # Parse JSON config using jq
        ALLOWED_PORTS=$(jq -r '.ports[]' "$config_file")
        ALLOWED_IP_RANGES=$(jq -r '.ip_ranges[]' "$config_file")
        # Process allowed processes (just an example - you can adapt it)
        ALLOWED_PROCESSES=$(jq -r '.processes | to_entries | .[] | "\(.key):\(.value | join(", "))"' "$config_file")
    fi
}
process_conn() {
    local line="$1"
    local proto=$(echo "$line" | awk '{print $1}')
    local ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
    local port=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
    local key="$proto:$ip:$port"
    if [[ ! " ${ALLOWED_PORTS[@]} " =~ " $port " ]] && ! ip_in_allowed_range "$ip"; then
        if ! rate_limited "$key"; then
            log_msg "Unusual outbound connection $key"
        fi
    fi
}
ip_in_allowed_range() {
    local ip="$1"
    for range in "${ALLOWED_IP_RANGES[@]}"; do
        if [[ "$ip" =~ $range ]]; then
            return 0
        fi
    done
    return 1
}
rate_limited() {
    local key="$1"
    local current_time=$(date +%s)
    if [[ -f "$key" && $(($current_time - $(cat "$key"))) -lt $RATE_LIMIT_SECONDS ]]; then
        return 0
    fi
    echo "$current_time" > "$key"
    return 1
}
monitor_network() {
    local continuous="$1"
    local once="$2"
    local duration="$3"

    # Disk Space Check (run in background)
    check_disk_space &
    # Monitor connections
    if [ "$once" == true ]; then
        ss -tun | tail -n +2 | while read -r line; do
            process_conn "$line"
        done
    fi
    if [ "$continuous" == true ]; then
        local start_time=$(date +%s)
        while true; do
            ss -tun | tail -n +2 | while read -r line; do
                process_conn "$line"
            done
            if [ "$duration" -gt 0 ]; then
                local elapsed_time=$(($(date +%s) - start_time))
                if [ "$elapsed_time" -ge "$duration" ]; then
                    break
                fi
            fi
            sleep 10
        done
    fi
}
print_help() {
    echo "Usage: portpeep [options]"
    echo "Options:"
    echo "  -h, --help                Show this help message"
    echo "  --continuous              Run continuously (poll every 10 seconds)"
    echo "  --once                    Run one-time scan and display results immediately"
    echo "  --learn                   Learn baseline instead of alerting"
    echo "  --terminal                Also log alerts to the terminal"
    echo "  --config <path>           Path to JSON config file"
    echo "  --duration <seconds>      Run for N seconds before exiting (continuous only)"
}
continuous=false
once=false
duration=0
learn=false
terminal=false
while [[ "$1" != "" ]]; do
    case $1 in
        -h | --help )          print_help; exit 0 ;;
        --continuous )         continuous=true ;;
        --once )               once=true ;;
        --learn )              learn=true ;;
        --terminal )           terminal=true ;;
        --config )             shift; load_config "$1" ;;
        --duration )           shift; duration="$1" ;;
        * )                    echo "Invalid option: $1"; exit 1 ;;
    esac
    shift
done
monitor_network "$continuous" "$once" "$duration"
