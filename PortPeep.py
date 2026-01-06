#!/usr/bin/python3
import subprocess
import logging
import psutil
import ipaddress
import os
import time
import argparse
from logging.handlers import RotatingFileHandler
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing  # For dynamic CPU-based thread pool
RATE_LIMIT_SECONDS = 60  # alert cooldown
DISK_SPACE_THRESHOLD = 1 * 1024 * 1024 * 1024  # 1 GB threshold for disk space
MAX_WORKERS = max(2, multiprocessing.cpu_count() * 2)  # Dynamic: 2 threads per CPU core, minimum 2
class NetworkMonitor:
    def __init__(self, terminal_output=False):
        self.ALLOWED_PORTS = {22, 53, 80, 443}
        self.ALLOWED_IP_RANGES = [
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('192.168.1.0/24'),
            ipaddress.IPv6Network('::1/128')  # IPv6 loopback
        ]
        self.alert_cache = {}
        self.terminal_output = terminal_output
        file_handler = RotatingFileHandler(
            '/var/log/network_monitor.log',
            maxBytes=5 * 1024 * 1024,
            backupCount=5
        )
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        handlers = [file_handler]
        if terminal_output:
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            handlers.append(console)
        # Safe logging setup
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        for h in handlers:
            root.addHandler(h)
    def check_disk_space(self):
        total, used, free = shutil.disk_usage("/")
        if free < DISK_SPACE_THRESHOLD:
            logging.error("Disk space is low! Stopping the script.")
            return False
        return True
    def rate_limited(self, key):
        now = time.time()
        last = self.alert_cache.get(key, 0)
        if now - last < RATE_LIMIT_SECONDS:
            logging.debug(f"Rate limit exceeded for {key}, skipping alert.")
            return True
        self.alert_cache[key] = now
        return False
    def clean_ip(self, ip):
        return ip.split('%')[0]
    def is_ip_allowed(self, dest_ip):
        try:
            ip_obj = ipaddress.ip_address(self.clean_ip(dest_ip))
            return any(ip_obj in net for net in self.ALLOWED_IP_RANGES)
        except ValueError:
            return False
    def extract_pid(self, text):
        if "pid=" not in text:
            return None
        try:
            return int(text.split("pid=")[1].split(",")[0])
        except (IndexError, ValueError):
            return None
    def get_active_connections(self):
        try:
            result = subprocess.run(['ss', '-tun'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    check=False)
            if not result.stdout:
                return []
            return result.stdout.decode().splitlines()[1:]
        except Exception as e:
            logging.debug(f"Error retrieving active connections: {e}")
            return []
    def get_process_connections(self):
        try:
            result = subprocess.run(['ss', '-tunp'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    check=False)
            if not result.stdout:
                return []
            return result.stdout.decode().splitlines()[1:]
        except Exception as e:
            logging.debug(f"Error retrieving process connections: {e}")
            return []
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
            if ip == "127.0.0.1" or ip == "::1":
                return
            if not port.isdigit():
                return
            port = int(port)
            alert_key = f"conn:{ip}:{port}:{proto}"
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
    def process_process(self, line):
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
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logging.warning(f"[ALERT] Unable to access process {pid}: {str(e)}")
        except Exception as e:
            logging.debug(f"Process error: {e}")
    def process_with_threadpool(self, lines, func):
        """Process connections or processes using a thread pool."""
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(func, line) for line in lines]
            for _ in as_completed(futures):
                pass  # Wait for all to finish
    def run(self, continuous=False):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Must be run as root.")
            return
        if not self.check_disk_space():
            return
        logging.info("Network monitor started")
        def run_once():
            self.process_with_threadpool(self.get_active_connections(), self.process_connection)
            self.process_with_threadpool(self.get_process_connections(), self.process_process)
        if continuous:
            while True:
                if not self.check_disk_space():
                    return
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
    if not any(vars(args).values()):
        parser.print_help()
        return
    monitor = NetworkMonitor(terminal_output=args.terminal)
    try:
        if args.continuous:
            monitor.run(continuous=True)
        else:
            monitor.run(continuous=False)
    except KeyboardInterrupt:
        print("\nMonitor stopped by user.")
if __name__ == "__main__":
    main()
