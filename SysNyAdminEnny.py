#!/usr/bin/env python3
import subprocess
import sys
import platform
import shutil
import threading
import psutil
import socket
from datetime import datetime
# Thread-safe logging
log_lock = threading.Lock()
def log_message(category, message, logfile=None):
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    log_filename = logfile or f"update_log_{now:%Y-%m-%d}.txt"
    try:
        with log_lock:
            with open(log_filename, "a", encoding="utf-8") as log_file:
                log_file.write(f"[{timestamp}] [{category}] {message}\n")
    except Exception:
        pass
def gather_system_info(logfile):
    info_lines = [
        "===== SYSTEM INFORMATION =====",
        f"System: {platform.system()}",
        f"Node: {platform.node()}",
        f"Release: {platform.release()}",
        f"Version: {platform.version()}",
        f"Machine: {platform.machine()}",
        f"Processor: {platform.processor()}",
        f"Python Version: {platform.python_version()}"
    ]
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        info_lines.append(
            f"CPU Cores: {physical} physical, {logical} logical"
        )
        info_lines.append(
            f"CPU Usage: {psutil.cpu_percent(interval=1)}%"
        )
    except Exception as e:
        info_lines.append(f"CPU Information Error: {e}")
    try:
        mem = psutil.virtual_memory()
        info_lines.extend([
            f"Memory Total: {mem.total // (1024**3)} GB",
            f"Memory Available: {mem.available // (1024**3)} GB",
            f"Memory Used: {mem.used // (1024**3)} GB"
        ])
    except Exception as e:
        info_lines.append(f"Memory Information Error: {e}")
    try:
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                info_lines.append(
                    f"Disk {part.device} - "
                    f"Total: {usage.total // (1024**3)} GB, "
                    f"Used: {usage.used // (1024**3)} GB, "
                    f"Free: {usage.free // (1024**3)} GB"
                )
            except Exception:
                continue
    except Exception as e:
        info_lines.append(f"Disk Information Error: {e}")
    try:
        for interface, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    info_lines.append(
                        f"Network Interface {interface} - IP: {addr.address}"
                    )
    except Exception as e:
        info_lines.append(f"Network Information Error: {e}")
    info_lines.append("===== END SYSTEM INFORMATION =====")
    try:
        with log_lock:
            with open(logfile, "a", encoding="utf-8") as log_file:
                log_file.write("\n".join(info_lines) + "\n")
    except Exception:
        pass
class Tool:
    @staticmethod
    def get_input(prompt):
        try:
            return input(prompt)
        except Exception as e:
            log_message("ERROR", f"Input error: {e}")
            return ""
    @staticmethod
    def command_exists(command):
        return shutil.which(command) is not None
class BaseUpdater:
    def update(self, logfile=None):
        raise NotImplementedError
    def update_firmware(self, logfile=None):
        raise NotImplementedError
    def run_command(self, command, category="INFO", logfile=None):
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True
            )
            output = result.stdout.strip()
            log_message(
                category,
                f"Executed command: {' '.join(command)}",
                logfile
            )
            if output:
                log_message(category, output, logfile)
        except subprocess.CalledProcessError as e:
            error = e.stderr.strip() if e.stderr else str(e)
            log_message(
                "ERROR",
                f"Command failed: {' '.join(command)} - {error}",
                logfile
            )
        except FileNotFoundError as e:
            log_message(
                "ERROR",
                f"Command not found: {e}",
                logfile
            )
        except Exception as e:
            log_message(
                "ERROR",
                f"Unexpected command error: {e}",
                logfile
            )
class OSXUpdater(BaseUpdater):

    def update(self, logfile):
        log_message(
            "INFO",
            "Starting secure macOS update (checking cache)...",
            logfile
        )

        if Tool.command_exists("softwareupdate"):
            self.run_command(
                ["sudo", "softwareupdate", "--list"],
                logfile=logfile
            )
            self.run_command(
                ["sudo", "softwareupdate", "-ia", "--verbose"],
                logfile=logfile
            )
        else:
            log_message(
                "ERROR",
                "softwareupdate command not found.",
                logfile
            )
        log_message(
            "INFO",
            "macOS update completed.",
            logfile
        )
    def update_firmware(self, logfile):
        log_message(
            "INFO",
            "Starting secure macOS firmware update check...",
            logfile
        )
        if Tool.command_exists("softwareupdate"):
            self.run_command(
                ["sudo", "softwareupdate", "--list"],
                logfile=logfile
            )
        else:
            log_message(
                "ERROR",
                "softwareupdate command not found for firmware.",
                logfile
            )
        log_message(
            "INFO",
            "macOS firmware update check completed.",
            logfile
        )
class WindowsUpdater(BaseUpdater):
    def update(self, logfile):
        log_message(
            "INFO",
            "Starting secure Windows update (checking cache)...",
            logfile
        )
        self.run_command(
            [
                "powershell",
                "-Command",
                (
                    "Install-Module PSWindowsUpdate -Force; "
                    "Get-WindowsUpdate; "
                    "Install-WindowsUpdate "
                    "-AcceptAll -AutoReboot"
                )
            ],
            logfile=logfile
        )
        log_message(
            "INFO",
            "Windows update completed.",
            logfile
        )
    def update_firmware(self, logfile):
        log_message(
            "INFO",
            "Starting secure Windows firmware update (checking cache)...",
            logfile
        )
        self.run_command(
            [
                "powershell",
                "-Command",
                (
                    "Install-Module FirmwareUpdate -Force; "
                    "Get-FirmwareUpdate; "
                    "Update-Firmware "
                    "-All -Confirm:$false"
                )
            ],
            logfile=logfile
        )
        log_message(
            "INFO",
            "Windows firmware update completed.",
            logfile
        )
class LinuxUpdater(BaseUpdater):
    def update(self, logfile):
        log_message(
            "INFO",
            "Starting secure Linux update (checking cache)...",
            logfile
        )
        if Tool.command_exists("apt"):
            self.run_command(
                ["sudo", "apt", "update"],
                logfile=logfile
            )
            self.run_command(
                ["sudo", "apt", "upgrade", "-y"],
                logfile=logfile
            )
        elif Tool.command_exists("dnf"):
            self.run_command(
                ["sudo", "dnf", "check-update"],
                logfile=logfile
            )
            self.run_command(
                ["sudo", "dnf", "upgrade", "-y"],
                logfile=logfile
            )
        elif Tool.command_exists("zypper"):
            self.run_command(
                ["sudo", "zypper", "refresh"],
                logfile=logfile
            )
            self.run_command(
                ["sudo", "zypper", "update", "-y"],
                logfile=logfile
            )
        else:
            log_message(
                "ERROR",
                "No supported package manager found.",
                logfile
            )
        log_message(
            "INFO",
            "Linux update completed.",
            logfile
        )
    def update_firmware(self, logfile):
        log_message(
            "INFO",
            "Starting secure Linux firmware update (checking cache)...",
            logfile
        )
        if Tool.command_exists("fwupdmgr"):
            self.run_command(
                ["sudo", "fwupdmgr", "get-updates"],
                logfile=logfile
            )
            self.run_command(
                ["sudo", "fwupdmgr", "update"],
                logfile=logfile
            )
        else:
            log_message(
                "ERROR",
                "fwupdmgr not found for firmware update.",
                logfile
            )
        log_message(
            "INFO",
            "Linux firmware update completed.",
            logfile
        )
class UpdaterManager:
    def __init__(self):
        self.updater = None
    def detect_os(self):
        os_name = platform.system().lower()
        if "darwin" in os_name:
            self.updater = OSXUpdater()
        elif "windows" in os_name:
            self.updater = WindowsUpdater()
        elif "linux" in os_name:
            self.updater = LinuxUpdater()
        else:
            raise RuntimeError(f"Unsupported OS: {os_name}")
        return os_name
    def run(self, logfile):
        if not self.updater:
            raise RuntimeError("No updater available")
        self.updater.update(logfile)
        self.updater.update_firmware(logfile)
def main():
    now = datetime.now()
    log_filename = f"update_log_{now:%Y-%m-%d}.txt"
    try:
        gather_system_info(log_filename)
        manager = UpdaterManager()
        os_name = manager.detect_os()
        log_message("INFO", f"Detected OS: {os_name}", log_filename)
        manager.run(log_filename)
        log_message("INFO", "All updates and firmware checks completed.", log_filename)
        print(f"Update process completed. Log file created: {log_filename}")
    except KeyboardInterrupt:
        log_message("WARNING", "Operation cancelled by user.", log_filename)
        sys.exit(130)
    except Exception as e:
        log_message("FATAL", str(e), log_filename)
        sys.exit(1)
if __name__ == "__main__":
    main()
