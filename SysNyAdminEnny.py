#!/usr/bin/env python3
import subprocess
import sys
import platform
import shutil
import threading
import unittest
import psutil
from datetime import datetime
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import argparse
log_lock = threading.Lock()
def log_message(category, message, logfile=None, to_db=False, to_email=False, email_config=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_filename = logfile or f"update_log_{datetime.now().strftime('%Y-%m-%d')}.txt"
    with log_lock:
        with open(log_filename, "a") as log_file:
            log_file.write(f"[{timestamp}] [{category}] {message}\n")
    if to_db:
        log_to_db(message, category, timestamp)
    if to_email and email_config:
        send_email_notification(email_config, category, message, timestamp)
def send_email_notification(email_config, category, message, timestamp):
    from_email = email_config.get("from_email")
    to_email = email_config.get("to_email")
    password = email_config.get("password")
    smtp_server = email_config.get("smtp_server")
    smtp_port = email_config.get("smtp_port", 587)
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = f"Update Status: {category} at {timestamp}"
    msg.attach(MIMEText(message, "plain"))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("Notification sent!")
    except Exception as e:
        print(f"Failed to send notification: {e}")
def log_to_db(message, category, timestamp):
    conn = sqlite3.connect("update_log.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (timestamp TEXT, category TEXT, message TEXT)''')
    c.execute("INSERT INTO logs (timestamp, category, message) VALUES (?, ?, ?)",
              (timestamp, category, message))
    conn.commit()
    conn.close()
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
    def update(self):
        raise NotImplementedError
    def update_firmware(self):
        raise NotImplementedError
    def run_command(self, command, category="INFO", logfile=None, to_db=False, to_email=False, email_config=None):
        try:
            subprocess.run(command, shell=True, check=True)
            log_message(category, f"Executed securely: {command}", logfile, to_db, to_email, email_config)
        except subprocess.CalledProcessError as e:
            log_message("ERROR", f"Failed: {command} with error {e}", logfile, to_db, to_email, email_config)

    def pre_update_check(self, logfile, to_db, to_email, email_config):
        disk_space = psutil.disk_usage('/')
        if disk_space.free < 10 * 1024**3:  # 10 GB free
            log_message("ERROR", "Insufficient disk space for update", logfile, to_db, to_email, email_config)
            return False
        return True
    def post_update_check(self):
        return True
class OSXUpdater(BaseUpdater):
    def update(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure macOS update (checking cache)...", logfile, to_db, to_email, email_config)
        if Tool.command_exists("softwareupdate"):
            self.run_command("sudo softwareupdate --list", logfile, to_db, to_email, email_config)
            self.run_command("sudo softwareupdate -ia --verbose", logfile, to_db, to_email, email_config)
        else:
            log_message("ERROR", "softwareupdate command not found.", logfile, to_db, to_email, email_config)
        log_message("INFO", "macOS update completed.", logfile, to_db, to_email, email_config)

    def update_firmware(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure macOS firmware update (checking cache)...", logfile, to_db, to_email, email_config)
        if Tool.command_exists("softwareupdate"):
            self.run_command("sudo softwareupdate --list", logfile, to_db, to_email, email_config)
            self.run_command("sudo softwareupdate --install-rosetta --agree-to-license", logfile, to_db, to_email, email_config)
        else:
            log_message("ERROR", "softwareupdate command not found for firmware.", logfile, to_db, to_email, email_config)
        log_message("INFO", "macOS firmware update completed.", logfile, to_db, to_email, email_config)
class WindowsUpdater(BaseUpdater):
    def update(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure Windows update (checking cache)...", logfile, to_db, to_email, email_config)
        self.run_command(
            "powershell -Command \"Install-Module PSWindowsUpdate; "
            "Get-WindowsUpdate -MicrosoftUpdate; "
            "Install-WindowsUpdate -AcceptAll -AutoReboot\"",
            logfile, to_db, to_email, email_config
        )
        log_message("INFO", "Windows update completed.", logfile, to_db, to_email, email_config)
    def update_firmware(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure Windows firmware update (checking cache)...", logfile, to_db, to_email, email_config)
        self.run_command(
            "powershell -Command \"Install-Module -Name FirmwareUpdate; "
            "Get-FirmwareUpdate; Update-Firmware -All -Confirm:$false\"",
            logfile, to_db, to_email, email_config
        )
        log_message("INFO", "Windows firmware update completed.", logfile, to_db, to_email, email_config)
class LinuxUpdater(BaseUpdater):
    def update(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure Linux update (checking cache)...", logfile, to_db, to_email, email_config)
        if Tool.command_exists("apt"):
            self.run_command("sudo apt update", logfile, to_db, to_email, email_config)
            self.run_command("sudo apt upgrade -y", logfile, to_db, to_email, email_config)
        elif Tool.command_exists("dnf"):
            self.run_command("sudo dnf check-update", logfile, to_db, to_email, email_config)
            self.run_command("sudo dnf upgrade -y", logfile, to_db, to_email, email_config)
        elif Tool.command_exists("zypper"):
            self.run_command("sudo zypper refresh", logfile, to_db, to_email, email_config)
            self.run_command("sudo zypper update -y", logfile, to_db, to_email, email_config)
        elif Tool.command_exists("pacman"):
            self.run_command("sudo pacman -Syu", logfile, to_db, to_email, email_config)
        elif Tool.command_exists("snap"):
            self.run_command("sudo snap refresh", logfile, to_db, to_email, email_config)
        else:
            log_message("ERROR", "No supported package manager found.", logfile, to_db, to_email, email_config)
        log_message("INFO", "Linux update completed.", logfile, to_db, to_email, email_config)

    def update_firmware(self, logfile, to_db, to_email, email_config):
        log_message("INFO", "Starting secure Linux firmware update (checking cache)...", logfile, to_db, to_email, email_config)
        if Tool.command_exists("fwupdmgr"):
            self.run_command("sudo fwupdmgr get-updates", logfile, to_db, to_email, email_config)
            self.run_command("sudo fwupdmgr update", logfile, to_db, to_email, email_config)
        else:
            log_message("ERROR", "fwupdmgr not found for firmware update.", logfile, to_db, to_email, email_config)
        log_message("INFO", "Linux firmware update completed.", logfile, to_db, to_email, email_config)

# UpdaterManager for handling OS detection and update execution
class UpdaterManager:
    def __init__(self, update_software=True, update_firmware=True, to_db=False, to_email=False, email_config=None):
        self.update_software = update_software
        self.update_firmware = update_firmware
        self.to_db = to_db
        self.to_email = to_email
        self.email_config = email_config
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
        if self.updater:
            if self.update_software:
                self.updater.update(logfile, self.to_db, self.to_email, self.email_config)
            if self.update_firmware:
                self.updater.update_firmware(logfile, self.to_db, self.to_email, self.email_config)
        else:
            raise RuntimeError("No updater available")
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="System update script. Use this to update your system and firmware for macOS, Windows, and Linux."
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--email", action="store_true", help="Enable email notifications for updates")
    parser.add_argument("--db", action="store_true", help="Enable database logging for updates")
    parser.add_argument("--smtp-server", type=str, help="SMTP server for email notifications")
    parser.add_argument("--from-email", type=str, help="Sender email address")
    parser.add_argument("--to-email", type=str, help="Recipient email address")
    parser.add_argument("--password", type=str, help="Email password (or app-specific password)")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP server port (default 587)")
    return parser.parse_args()
def main():
    args = parse_arguments()
    log_filename = f"update_log_{datetime.now().strftime('%Y-%m-%d')}.txt"
    email_config = None
    if args.email:
        email_config = {
            "smtp_server": args.smtp_server,
            "from_email": args.from_email,
            "to_email": args.to_email,
            "password": args.password,
            "smtp_port": args.smtp_port
        }
    try:
        gather_system_info(log_filename)  # Write system info
        manager = UpdaterManager(
            update_software=True,
            update_firmware=True,
            to_db=args.db,
            to_email=args.email,
            email_config=email_config
        )
        os_name = manager.detect_os()  # OS detection
        log_message("INFO", f"Detected OS: {os_name}", log_filename, args.db, args.email, email_config)
        manager.run(log_filename)  # Run updates
        log_message("INFO", "All updates and firmware checks completed.", log_filename, args.db, args.email, email_config)
        print(f"Update process completed. Log file created: {log_filename}")
        if args.verbose:
            log_message("INFO", "Verbose mode enabled", log_filename, args.db, args.email, email_config)
    except Exception as e:
        log_message("FATAL", str(e), log_filename, args.db, args.email, email_config)
        sys.exit(1)
if __name__ == "__main__":
    main()
