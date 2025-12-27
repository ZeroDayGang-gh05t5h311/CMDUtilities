import subprocess
import logging
import psutil
import ipaddress
import os
import threading
import time
import argparse
from logging.handlers import RotatingFileHandler
RATE_LIMIT_SECONDS = 60  # alert cooldown
class NetworkMonitor:
    def __init__(self, terminal_output=False):
        self.ALLOWED_PORTS = {22, 53, 80, 443}
        self.ALLOWED_IP_RANGES = [
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('192.168.1.0/24')
        ]
        self.alert_cache = {}
        self.terminal_output = terminal_output
        file_handler = RotatingFileHandler(
            '/var/log/network_monitor.log',
            maxBytes=5 * 1024 * 1024,
            backupCount=5
        )
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        handlers = [file_handler]
        if terminal_output:
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            handlers.append(console)
        logging.basicConfig(level=logging.INFO, handlers=handlers)
    def rate_limited(self, key):
        now = time.time()
        last = self.alert_cache.get(key, 0)
        if now - last < RATE_LIMIT_SECONDS:
            return True
        self.alert_cache[key] = now
        return False
    def clean_ip(self, ip):
        return ip.split('%')[0]
    def is_ip_allowed(self, dest_ip):
        try:
            ip = ipaddress.IPv4Address(self.clean_ip(dest_ip))
            return any(ip in net for net in self.ALLOWED_IP_RANGES)
        except ipaddress.AddressValueError:
            return False
    def extract_pid(self, text):
        if "pid=" not in text:
            return None
        try:
            return int(text.split("pid=")[1].split(",")[0])
        except (IndexError, ValueError):
            return None
    def get_active_connections(self):
        result = subprocess.run(['ss', '-tun'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.stdout.decode().splitlines()[1:]
    def get_process_connections(self):
        result = subprocess.run(['ss', '-tunp'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.stdout.decode().splitlines()[1:]
    def process_connection(self, line):
        try:
            columns = line.split()
            if len(columns) < 5:
                return
            proto = columns[0]
            dest = columns[4]
            if ':' not in dest:
                return
            ip, port = dest.rsplit(':', 1)
            ip = self.clean_ip(ip)
            if not port.isdigit():
                return
            port = int(port)
            alert_key = f"conn:{ip}:{port}"

            if port not in self.ALLOWED_PORTS and not self.is_ip_allowed(ip):
                if self.rate_limited(alert_key):
                    return
                logging.warning("[ALERT] Unusual outbound connection")
                logging.warning(f"Protocol: {proto}")
                logging.warning(f"Destination: {ip}:{port}")
            else:
                logging.info(f"[OK] {proto} -> {ip}:{port}")
        except Exception as e:
            logging.debug(f"Connection error: {e}")
    def process_connections_in_thread(self, lines):
        threads = []
        for line in lines:
            t = threading.Thread(target=self.process_connection, args=(line,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    def process_processes(self, line):
        try:
            columns = line.split()
            if len(columns) < 6:
                return
            pid = self.extract_pid(line)
            if pid is None:
                return
            dest = columns[4]
            if ':' not in dest:
                return
            port = dest.rsplit(':', 1)[-1]
            if not port.isdigit():
                return
            port = int(port)
            alert_key = f"proc:{pid}:{port}"
            if port not in self.ALLOWED_PORTS:
                if self.rate_limited(alert_key):
                    return
                try:
                    proc = psutil.Process(pid)
                    logging.warning("[ALERT] Process using non-standard port")
                    logging.warning(f"Process: {proc.name()} (PID {pid})")
                    logging.warning(f"Port: {port}")
                except psutil.Error:
                    logging.warning(f"[ALERT] Unknown PID {pid} on port {port}")
        except Exception as e:
            logging.debug(f"Process error: {e}")            
    def process_processes_in_thread(self, lines):
        threads = []
        for line in lines:
            t = threading.Thread(target=self.process_processes, args=(line,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    # ---------- Runner ----------
    def run(self, continuous=False):
        if os.geteuid() != 0:
            print("Must be run as root.")
            return
        logging.info("Network monitor started")
        def run_once():
            self.process_connections_in_thread(self.get_active_connections())
            self.process_processes_in_thread(self.get_process_connections())
        if continuous:
            while True:
                run_once()
                time.sleep(10)
        else:
            run_once()
            logging.info("One-time network scan completed")
def main():
    parser = argparse.ArgumentParser(description="Network Monitor")
    parser.add_argument("-c", "--continuous", action="store_true", help="Run continuously")
    parser.add_argument("-o", "--one-time", action="store_true", help="Run once")
    parser.add_argument("--terminal", action="store_true", help="Output to terminal as well as log")
    args = parser.parse_args()
    monitor = NetworkMonitor(terminal_output=args.terminal)
    if args.continuous:
        monitor.run(continuous=True)
    else:
        monitor.run(continuous=False)
if __name__ == "__main__":
    main()
"""
Flag    Meaning
(default)   One-time scan → log only
-o  One-time scan → log only
-c  Continuous scan → log only
--terminal  ALSO print alerts/info to terminal
-c --terminal   Continuous + terminal + log
-o --terminal   One-time + terminal + log
"""
