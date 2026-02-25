#!/usr/bin/python3
import subprocess
import logging
import psutil
import ipaddress
import os
import time
import argparse
import json
import csv
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
RATE_LIMIT_SECONDS = 60
DISK_SPACE_THRESHOLD = 1 * 1024 * 1024 * 1024
MAX_WORKERS = max(2, multiprocessing.cpu_count() * 2)
BASELINE_FILE = "baseline.json"
class NetworkMonitor:
    def __init__(self, terminal_output=False, config=None, learn=False,
                 export_csv=None, export_json=None):
        self.learn = learn
        self.export_csv = export_csv
        self.export_json = export_json
        self.alerts = []
        self.ALLOWED_PORTS = {22, 53, 80, 443}
        self.ALLOWED_IP_RANGES = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("192.168.1.0/24"),
            ipaddress.ip_network("::1/128")
        ]
        self.ALLOWED_PROCESSES = {}
        self.baseline = {"connections": set(), "process_ports": set()}
        self.load_baseline()
        if config:
            self.load_config(config)
        self.alert_cache = {}
        self.terminal_output = terminal_output
        root = logging.getLogger()
        if not root.handlers:
            handler = RotatingFileHandler(
                "/var/log/network_monitor.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=5
            )
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            root.setLevel(logging.INFO)
            root.addHandler(handler)
            if terminal_output:
                console = logging.StreamHandler()
                console.setFormatter(formatter)
                root.addHandler(console)
    def load_config(self, path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        self.ALLOWED_PORTS |= set(cfg.get("ports", []))
        self.ALLOWED_IP_RANGES.extend(
            ipaddress.ip_network(n) for n in cfg.get("ip_ranges", [])
        )
        self.ALLOWED_PROCESSES = cfg.get("processes", {})
    def load_baseline(self):
        if os.path.exists(BASELINE_FILE):
            with open(BASELINE_FILE, encoding="utf-8") as f:
                data = json.load(f)
                self.baseline["connections"] = set(data.get("connections", []))
                self.baseline["process_ports"] = set(data.get("process_ports", []))
    def save_baseline(self):
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "connections": list(self.baseline["connections"]),
                    "process_ports": list(self.baseline["process_ports"])
                },
                f,
                indent=2
            )
    def rate_limited(self, key):
        now = time.time()
        last = self.alert_cache.get(key, 0)
        if now - last < RATE_LIMIT_SECONDS:
            return True
        self.alert_cache[key] = now
        return False
    @staticmethod
    def clean_ip(ip):
        return ip.split("%", 1)[0]

    def is_ip_allowed(self, ip):
        try:
            addr = ipaddress.ip_address(self.clean_ip(ip))
            return any(addr in net for net in self.ALLOWED_IP_RANGES)
        except ValueError:
            return False
    @staticmethod
    def get_ss(args):
        try:
            r = subprocess.run(
                ["ss"] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False
            )
            return r.stdout.decode().splitlines()[1:]
        except Exception:
            return []
    def process_connection(self, line):
        cols = line.split()
        if len(cols) < 6:
            return
        proto = cols[0]
        dest = cols[4]
        if ":" not in dest:
            return
        ip, port = dest.rsplit(":", 1)
        if not port.isdigit():
            return
        port = int(port)
        key = f"{proto}:{ip}:{port}"
        if self.learn:
            self.baseline["connections"].add(key)
            return
        if key in self.baseline["connections"]:
            return
        if port not in self.ALLOWED_PORTS and not self.is_ip_allowed(ip):
            if self.rate_limited(key):
                return
            msg = f"Unusual outbound connection {proto} {ip}:{port}"
            logging.warning(msg)
            self.alerts.append(msg)
    def process_process(self, line):
        if "pid=" not in line:
            return
        try:
            pid = int(line.split("pid=", 1)[1].split(",", 1)[0])
            proc = psutil.Process(pid)
        except Exception:
            return
        cols = line.split()
        if len(cols) < 6:
            return
        dest = cols[4]
        if ":" not in dest:
            return
        port = dest.rsplit(":", 1)[-1]
        if not port.isdigit():
            return
        port = int(port)
        pname = proc.name()
        key = f"{pname}:{port}"
        if self.learn:
            self.baseline["process_ports"].add(key)
            return
        if key in self.baseline["process_ports"]:
            return
        allowed_ports = self.ALLOWED_PROCESSES.get(pname, [])
        if port not in allowed_ports and port not in self.ALLOWED_PORTS:
            if self.rate_limited(key):
                return
            msg = f"Process {pname} (PID {pid}) using port {port}"
            logging.warning(msg)
            self.alerts.append(msg)
    def run(self, continuous=False, once=False, duration=None):
        if os.geteuid() != 0:
            print("Must be run as root.")
            return
        def once_scan():
            conns = self.get_ss(["-tun"])
            procs = self.get_ss(["-tunp"])
            with ThreadPoolExecutor(MAX_WORKERS) as ex:
                for l in conns:
                    ex.submit(self.process_connection, l)
                for l in procs:
                    ex.submit(self.process_process, l)
        start_time = time.time()
        if once:
            self.terminal_output = True
            once_scan()
            self._print_terminal_summary()
            if self.learn:
                self.save_baseline()
            return
        if continuous:
            while True:
                once_scan()
                if duration and (time.time() - start_time) >= duration:
                    break
                time.sleep(10)
        else:
            once_scan()
        if self.learn:
            self.save_baseline()
        if self.export_csv:
            with open(self.export_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                for a in self.alerts:
                    w.writerow([a])
        if self.export_json:
            with open(self.export_json, "w", encoding="utf-8") as f:
                json.dump(self.alerts, f, indent=2)
    def _print_terminal_summary(self):
        if not self.alerts:
            print("\nNo alerts detected.")
            return
        print("\n=== Network Monitor Alerts Summary ===")
        for i, a in enumerate(self.alerts, 1):
            print(f"{i}. {a}")
        print("=====================================\n")
def main():
    p = argparse.ArgumentParser(
        description="Network connection and process monitor with baseline learning"
    )
    p.add_argument("-c", "--continuous", action="store_true",
                   help="Run continuously (poll every 10 seconds)")
    p.add_argument("--terminal", action="store_true",
                   help="Also log alerts to the terminal")
    p.add_argument("--config", help="Path to JSON config file")
    p.add_argument("--learn", action="store_true",
                   help="Learn baseline instead of alerting")
    p.add_argument("--export-csv", help="Export alerts to CSV file")
    p.add_argument("--export-json", help="Export alerts to JSON file")
    p.add_argument("--once", action="store_true",
                   help="Run one-time scan and display results immediately")
    p.add_argument("--duration", type=int,
                   help="Run for N seconds before exiting (continuous only)")
    args = p.parse_args()
    m = NetworkMonitor(
        terminal_output=args.terminal,
        config=args.config,
        learn=args.learn,
        export_csv=args.export_csv,
        export_json=args.export_json
    )
    m.run(
        continuous=args.continuous,
        once=args.once,
        duration=args.duration
    )
if __name__ == "__main__":
    main()
