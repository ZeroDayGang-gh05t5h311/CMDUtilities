#!/usr/bin/bash
# You need to run this as root!
if [ "$(id -u)" -ne 0 ]; then
    echo "In order to run this you need to be root!"
    exit 1
fi
# Define allowed ports (SSH, DNS, HTTP, HTTPS)
ALLOWED_PORTS="22 53 80 443"
# Define allowed IP ranges (e.g., localhost and some trusted network)
ALLOWED_IP_RANGES="127.0.0.0/8 192.168.1.0/24"
# Check active connections using ss, then process each line
ss -tun | tail -n +2 | while read line; do
    DEST_IP=$(echo "$line" | awk '{print $5}' | awk -F: '{print $1}' | sed 's/%.*//')  # Remove network interface suffix
    DEST_PORT=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
    PROTOCOL=$(echo "$line" | awk '{print $1}')
    if ! echo "$ALLOWED_PORTS" | grep -qw "$DEST_PORT"; then
        IP_MATCH=0
        for range in $ALLOWED_IP_RANGES; do
            # Use ipcalc or another method to check if DEST_IP is in the allowed range
            if ipcalc -n "$range" | grep -q "$DEST_IP"; then
                IP_MATCH=1
                break
            fi
        done
        if [ "$IP_MATCH" -eq 0 ]; then
            echo "[ALERT] Unusual outbound connection detected!"
            echo "Protocol: $PROTOCOL"
            echo "Destination IP: $DEST_IP"
            echo "Destination Port: $DEST_PORT"
            echo "Reason: Port $DEST_PORT is not in the allowed list and the destination IP is not in the allowed IP ranges."
        fi
    else
        echo "[INFO] Allowed outbound connection."
        echo "Protocol: $PROTOCOL"
        echo "Destination IP: $DEST_IP"
        echo "Destination Port: $DEST_PORT"
    fi
done
# Now, let's check for non-standard ports used by running processes
echo "[INFO] Checking for processes using non-standard ports..."
ss -tunp | tail -n +2 | while read line; do
    # Extract the PID and process info from ss
    pid_info=$(echo "$line" | awk '{print $6}' | cut -d',' -f2 | cut -d'=' -f2)
    process_port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}' | head -n 1)
    # Check if the process uses a non-standard port
    if ! echo "$ALLOWED_PORTS" | grep -qw "$process_port"; then
        # If it's a valid PID, get the process name
        if [[ "$pid_info" =~ ^[0-9]+$ ]]; then
            process_name=$(ps -p "$pid_info" -o comm=)
            echo "[ALERT] Process with PID $pid_info is using a non-standard port!"
            echo "Process Name: $process_name"
            echo "Process PID: $pid_info"
            echo "Port: $process_port"
        fi
    fi
done
