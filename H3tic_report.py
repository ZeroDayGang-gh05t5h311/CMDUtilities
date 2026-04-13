#!/usr/bin/python3
"""
h3ktic_report.py
Linux system compromise checker for novice users with scoring, risk classification, detailed follow-up steps,
and prioritization recommendations.
Outputs a human-readable report in the current directory.
"""
import os
import subprocess
from datetime import datetime
# ANSI color codes for terminal highlighting
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"
TOTAL_SCORE = 0  # cumulative speciousness score
SECTION_SCORES = {}  # track individual section scores for prioritization
def get_report_filename():
    """Generate a unique report filename to avoid duplicates."""
    base_name = f"compromise_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    filename = base_name + ".txt"
    counter = 1
    while os.path.exists(filename):
        filename = f"{base_name}_{counter}.txt"
        counter += 1
    return filename
REPORT_FILE = get_report_filename()
def write_report(text, color=None):
    """Write text to report file and optionally colorize in terminal."""
    if color:
        print(color + text + RESET)
    else:
        print(text)
    with open(REPORT_FILE, "a") as f:
        f.write(text + "\n")
def section(title):
    """Write a formatted section header."""
    write_report("\n" + "=" * 80)
    write_report(f"=== {title} ===")
    write_report("=" * 80 + "\n")
def run_cmd(cmd, explanation=None, warning=None):
    """Run a shell command with optional explanation and warnings. Returns count of output lines."""
    if explanation:
        write_report(f"INFO: {explanation}\n")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
        output_lines = output.strip().splitlines()
        if output_lines:
            write_report("\n".join(output_lines))
            return len(output_lines)
        else:
            write_report("No output found.")
            if warning:
                write_report(f"WARNING: {warning}", RED)
            return 0
    except subprocess.CalledProcessError:
        write_report("Command failed or produced no output.", RED)
        if warning:
            write_report(f"WARNING: {warning}", RED)
        return 0
def score_section(count, max_points=10):
    """Assign a suspiciousness score based on the number of findings."""
    if count == 0:
        return 0
    return min(max_points, count)
def follow_up_instructions(section_name):
    """Return detailed steps for investigating each section."""
    instructions = {
        "Suspicious Processes": [
            "1. Note the process names and their PID.",
            "2. Check executable paths: `ls -l /proc/<PID>/exe`",
            "3. Use `top -p <PID>` or `ps -fp <PID>` to monitor resource usage.",
            "4. Research process names online for malware indicators.",
            "5. Terminate and remove confirmed malicious processes."
        ],
        "Hidden Files": [
            "1. Identify hidden files and owners: `ls -la <path>`",
            "2. Check permissions: `stat <file>`",
            "3. Examine contents with `cat`, `less`, or `strings`.",
            "4. Compare file hashes with known-good sources if available.",
            "5. Remove suspicious files if safe."
        ],
        "Network Activity": [
            "1. Identify unusual open ports and remote connections.",
            "2. Use `lsof -i :<port>` to find associated process.",
            "3. Research IP addresses/domains online.",
            "4. Block suspicious connections using firewall rules.",
            "5. Monitor for recurring anomalies."
        ],
        "Recently Modified System Binaries": [
            "1. Verify which files were modified and their hashes.",
            "2. Compare with known-good checksums if available.",
            "3. Check package manager logs for legitimate updates.",
            "4. Restore or reinstall binaries if unauthorized."
        ],
        "Users and Groups": [
            "1. Review unexpected users with UID < 1000.",
            "2. Check login history and password changes.",
            "3. Remove unauthorized accounts with `userdel`.",
            "4. Ensure sudo privileges are only for trusted accounts."
        ],
        "Sudoers and Cron Jobs": [
            "1. Examine cron jobs for unusual scripts or schedules.",
            "2. Check sudoers for unknown users or rules.",
            "3. Remove suspicious entries carefully.",
            "4. Monitor for recurring re-creation."
        ],
        "Kernel Modules": [
            "1. Investigate unknown kernel modules.",
            "2. Check module origin: `modinfo <module>`",
            "3. Remove unauthorized modules using `rmmod` if safe.",
            "4. Monitor system for rootkit signs."
        ],
        "Last Logins": [
            "1. Verify unfamiliar login entries.",
            "2. Cross-check with logs in `/var/log`.",
            "3. Investigate source IP addresses.",
            "4. Change passwords if unauthorized access suspected."
        ]
    }
    return instructions.get(section_name, [])
def check_section(name, cmd, explanation, warning):
    """Check a section and return its score."""
    count = run_cmd(cmd, explanation, warning)
    score = score_section(count)
    SECTION_SCORES[name] = score
    color = YELLOW if score > 0 else GREEN
    write_report(f"{name} Score: {score}/10\n", color)
    instructions = follow_up_instructions(name)
    if instructions:
        write_report("Follow-up Investigation Steps:", YELLOW)
        for step in instructions:
            write_report(f" - {step}")
    write_report("")
    return score
def main():
    global TOTAL_SCORE
    section("Enhanced Linux System Compromise Check - Beginner Friendly")
    write_report(f"Report generated on: {datetime.now()}")
    write_report(f"Hostname: {os.uname().nodename}\n")
    write_report("NOTE: Warnings in red indicate areas that may require further investigation.\n")
    # Check sections
    TOTAL_SCORE += check_section(
        "Suspicious Processes",
        "ps aux | awk '$11 ~ /^\\/tmp|^\\/var\\/tmp|^\\/dev\\/shm|/^\\..+/'",
        "Processes running from unusual or hidden directories may be malicious.",
        "Processes found here may indicate a compromise!"
    )
    TOTAL_SCORE += check_section(
        "Hidden Files",
        "find /tmp /var/tmp /home /root -type f -name '.*'",
        "Hidden files may be used to hide malicious scripts.",
        "Hidden files found may be suspicious!"
    )
    TOTAL_SCORE += check_section(
        "Network Activity",
        "ss -tulnp || netstat -tulnp",
        "Shows listening ports and active connections.",
        "Unusual network connections may indicate compromise!"
    )
    TOTAL_SCORE += check_section(
        "Recently Modified System Binaries",
        "find /bin /usr/bin /sbin /usr/sbin -type f -mtime -7",
        "System binaries rarely change. Recent modifications may indicate tampering.",
        "Modified system binaries may be a sign of compromise!"
    )
    TOTAL_SCORE += check_section(
        "Users and Groups",
        "awk -F: '$3 < 1000 {print $1, $3}' /etc/passwd",
        "Users with UID < 1000 are usually system users.",
        "Suspicious users detected!"
    )
    TOTAL_SCORE += check_section(
        "Sudoers and Cron Jobs",
        "cat /etc/sudoers && find /etc/cron.* /var/spool/cron -type f -exec cat {} \\;",
        "Check administrative privileges and scheduled tasks.",
        "Unexpected entries may indicate compromise!"
    )
    TOTAL_SCORE += check_section(
        "Kernel Modules",
        "lsmod",
        "Shows loaded kernel modules. Unknown modules may indicate rootkits.",
        "Unknown kernel modules may indicate compromise!"
    )
    TOTAL_SCORE += check_section(
        "Last Logins",
        "last -n 10",
        "Shows last login activity. Unfamiliar logins may indicate unauthorized access.",
        "Unexpected logins may indicate compromise!"
    )
    # Risk classification
    section("System Risk Classification")
    if TOTAL_SCORE < 20:
        risk = "Low Risk"
        color = GREEN
    elif TOTAL_SCORE < 50:
        risk = "Medium Risk"
        color = YELLOW
    else:
        risk = "High Risk"
        color = RED
    write_report(f"TOTAL SUSPICIOUSNESS SCORE: {TOTAL_SCORE}/80", color)
    write_report(f"SYSTEM RISK LEVEL: {risk}", color)
    # Prioritization recommendation
    section("Investigation Prioritization Recommendation")
    write_report("Prioritize investigation on sections with higher scores first:\n", YELLOW)
    sorted_sections = sorted(SECTION_SCORES.items(), key=lambda x: x[1], reverse=True)
    for name, score in sorted_sections:
        write_report(f" - {name}: {score}/10")
    write_report(f"\nReport saved to {os.path.abspath(REPORT_FILE)}")
    write_report("Follow the investigation steps above, starting with the highest")
if __name__ == "__main__":
    main() 
""""
working from home on finding vulnerability's mostly but also a few updates to this GitHub here and there.
""""
