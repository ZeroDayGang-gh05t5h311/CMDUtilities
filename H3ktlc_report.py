#!/usr/bin/python3
"""
h3ktlc_report.py
Multi Platform System compromise checker with scoring, forensic analysis,
parallel checks, severity classification, JSON/HTML reporting and baselines.
Read-only security auditing tool.
"""
import os
import sys
import json
import time
import html
import shutil
import hashlib
import argparse
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor,as_completed
RED="\033[91m"
YELLOW="\033[93m"
GREEN="\033[92m"
CYAN="\033[96m"
RESET="\033[0m"
DEFAULT_REPORT_PREFIX="compromise_report"
BASELINE_FILE="h3ktic_baseline.json"
SEVERITY_LEVELS={
    "INFO":0,
    "LOW":1,
    "MEDIUM":2,
    "HIGH":3,
    "CRITICAL":4
}
class CheckResult:
    def __init__(
        self,
        name,
        success=False,
        output=None,
        error="",
        severity="INFO",
        score=0,
        category="general",
        details=""
    ):
        self.name=name
        self.success=success
        self.output=output or []
        self.error=error
        self.severity=severity
        self.score=score
        self.category=category
        self.details=details
        self.timestamp=str(datetime.now())
    def to_dict(self):
        return {
            "name":self.name,
            "success":self.success,
            "output":self.output,
            "error":self.error,
            "severity":self.severity,
            "score":self.score,
            "category":self.category,
            "details":self.details,
            "timestamp":self.timestamp
        }
class ReportWriter:
    def __init__(self,filename,verbose=False):
        self.filename=filename
        self.verbose=verbose
        self.results=[]
        self.lines=[]
    def write(self,text,color=None):
        self.lines.append(text)
        if color:
            print(color+text+RESET)
        else:
            print(text)
        try:
            with open(self.filename,"a",encoding="utf-8") as f:
                f.write(text+"\n")
        except Exception as e:
            print(RED+"Report error: "+str(e)+RESET)
    def section(self,title):
        self.write("="*80)
        self.write("=== "+title+" ===")
        self.write("="*80)
    def add_result(self,result):
        self.results.append(result)
    def severity_output(self,severity):
        if severity=="CRITICAL":
            return RED
        if severity=="HIGH":
            return RED
        if severity=="MEDIUM":
            return YELLOW
        if severity=="LOW":
            return CYAN
        return GREEN
def create_report_filename(directory="."):
    base=datetime.now().strftime(DEFAULT_REPORT_PREFIX+"_%Y%m%d_%H%M%S")
    path=Path(directory)
    filename=path/(base+".txt")
    count=1
    while filename.exists():
        filename=path/(base+"_"+str(count)+".txt")
        count+=1
    return str(filename)
def command_exists(command):
    return shutil.which(command) is not None
def is_root():
    if hasattr(os,"geteuid"):
        return os.geteuid()==0
    return False
def execute_command(command,timeout=30):
    start=time.time()
    try:
        result=subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "code":result.returncode,
            "output":result.stdout.strip().splitlines() if result.stdout.strip() else [],
            "error":result.stderr.strip(),
            "time":round(time.time()-start,3)
        }
    except subprocess.TimeoutExpired:
        return {
            "code":-1,
            "output":[],
            "error":"Command timed out",
            "time":round(time.time()-start,3)
        }
    except FileNotFoundError:
        return {
            "code":-1,
            "output":[],
            "error":"Command not found",
            "time":round(time.time()-start,3)
        }
    except Exception as e:
        return {
            "code":-1,
            "output":[],
            "error":str(e),
            "time":round(time.time()-start,3)
        }
def determine_severity(lines,category):
    count=len(lines)
    if count==0:
        return "INFO"
    high_categories=[
        "rootkit",
        "privilege",
        "persistence",
        "network"
    ]
    if category in high_categories and count>10:
        return "HIGH"
    if category in high_categories:
        return "MEDIUM"
    if count>50:
        return "MEDIUM"
    return "LOW"
def calculate_score(lines,weight=1,severity="INFO"):
    if not lines:
        return 0
    base=min(10,len(lines)*weight)
    multiplier={
        "INFO":0,
        "LOW":1,
        "MEDIUM":2,
        "HIGH":3,
        "CRITICAL":5
    }
    return min(10,base*multiplier.get(severity,1))
def run_check(
    writer,
    name,
    command,
    explanation,
    warning,
    required_tools=None,
    weight=1,
    category="general"
):
    writer.write("")
    writer.write("Running check: "+name,CYAN)
    writer.write("INFO: "+explanation)
    if required_tools:
        missing=[]
        for tool in required_tools:
            if not command_exists(tool):
                missing.append(tool)
        if missing:
            result=CheckResult(
                name,
                False,
                [],
                "Missing tools: "+", ".join(missing),
                "LOW",
                0,
                category
            )
            writer.add_result(result)
            writer.write(
                "SKIPPED: Missing tools: "+", ".join(missing),
                YELLOW
            )
            return result
    data=execute_command(command)
    severity=determine_severity(
        data["output"],
        category
    )
    score=calculate_score(
        data["output"],
        weight,
        severity
    )
    result=CheckResult(
        name,
        data["code"]==0,
        data["output"],
        data["error"],
        severity,
        score,
        category,
        warning
    )
    writer.add_result(result)
    for line in data["output"]:
        writer.write(line)
    if data["error"]:
        writer.write(
            "Command warning: "+data["error"],
            YELLOW
        )
    if data["output"]:
        writer.write(
            "Severity: "+severity,
            writer.severity_output(severity)
        )
        writer.write(
            "WARNING: "+warning,
            writer.severity_output(severity)
        )
    writer.write(
        name+" Score: "+str(score)+"/10",
        writer.severity_output(severity)
    )
    if writer.verbose:
        writer.write(
            "Execution time: "+
            str(data["time"])+
            " seconds",
            CYAN
        )
    return result
def run_parallel_checks(writer,checks,workers=4):
    total=[]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        jobs=[]
        for check in checks:
            jobs.append(
                executor.submit(
                    run_check,
                    writer,
                    *check
                )
            )
        for job in as_completed(jobs):
            total.append(job.result())
    return total
def get_system_type():
    return platform.system().lower()
def get_system_info():
    return {
        "system":platform.system(),
        "release":platform.release(),
        "version":platform.version(),
        "machine":platform.machine(),
        "hostname":platform.node(),
        "python":platform.python_version(),
        "root":is_root()
    }
def hash_file(path):
    try:
        digest=hashlib.sha256()
        with open(path,"rb") as f:
            for block in iter(lambda:f.read(65536),b""):
                digest.update(block)
        return digest.hexdigest()
    except Exception:
        return ""
def safe_walk(path):
    try:
        for root,dirs,files in os.walk(path):
            for item in files:
                yield os.path.join(root,item)
    except Exception:
        return
def find_recent_files(paths,days=7):
    found=[]
    now=time.time()
    age=days*86400
    for path in paths:
        if not os.path.exists(path):
            continue
        for item in safe_walk(path):
            try:
                if now-os.path.getmtime(item)<=age:
                    found.append(item)
            except Exception:
                pass
    return found
def linux_process_analysis():
    findings=[]
    proc="/proc"
    if not os.path.exists(proc):
        return findings
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        pid=entry
        exe=os.path.join(proc,pid,"exe")
        cmd=os.path.join(proc,pid,"cmdline")
        try:
            target=os.readlink(exe)
            if (
                target.startswith("/tmp") or
                target.startswith("/var/tmp") or
                target.startswith("/dev/shm")
            ):
                findings.append(
                    "PID: "+pid+
                    " EXEC: "+target
                )
            if target.endswith("(deleted)"):
                findings.append(
                    "PID: "+pid+
                    " deleted executable: "+
                    target
                )
        except Exception:
            pass
        try:
            with open(cmd,"r",encoding="utf-8",errors="ignore") as f:
                command=f.read().replace("\0"," ")
                if command:
                    if "curl" in command or "wget" in command:
                        findings.append(
                            "PID: "+pid+
                            " download command: "+
                            command
                        )
        except Exception:
            pass
    return findings
def linux_network_analysis():
    findings=[]
    if not command_exists("ss"):
        return findings
    data=execute_command(
        ["ss","-tunlp"]
    )
    for line in data["output"]:
        if (
            ":4444" in line or
            ":1337" in line or
            ":31337" in line
        ):
            findings.append(line)
    return findings
def linux_package_verify():
    findings=[]
    if command_exists("dpkg"):
        result=execute_command(
            ["dpkg","-V"]
        )
        findings=result["output"]
    elif command_exists("rpm"):
        result=execute_command(
            ["rpm","-Va"]
        )
        findings=result["output"]
    return findings
def linux_checks(writer):
    score=0
    checks=[
        (
            "Suspicious Processes",
            ["bash","-c","ps aux --sort=-%cpu"],
            "Collects running process information.",
            "Review unusual processes and executable locations.",
            ["bash","ps"],
            1,
            "process"
        ),
        (
            "Hidden Files",
            [
                "find",
                "/tmp",
                "/var/tmp",
                "/home",
                "/root",
                "-type",
                "f",
                "-name",
                ".*"
            ],
            "Searches common hiding locations.",
            "Hidden files require investigation.",
            ["find"],
            1,
            "filesystem"
        ),
        (
            "Network Activity",
            [
                "ss",
                "-tunlp"
            ],
            "Checks network listeners.",
            "Unexpected services require review.",
            ["ss"],
            2,
            "network"
        ),
        (
            "Kernel Modules",
            [
                "lsmod"
            ],
            "Lists loaded kernel modules.",
            "Unknown modules require investigation.",
            ["lsmod"],
            1,
            "rootkit"
        )
    ]
    results=run_parallel_checks(
        writer,
        checks
    )
    for result in results:
        score+=result.score
    extra=[
        (
            "Process Path Analysis",
            linux_process_analysis(),
            "process"
        ),
        (
            "Network Risk Analysis",
            linux_network_analysis(),
            "network"
        ),
        (
            "Package Verification",
            linux_package_verify(),
            "filesystem"
        )
    ]
    for name,data,category in extra:
        severity=determine_severity(
            data,
            category
        )
        result=CheckResult(
            name,
            True,
            data,
            "",
            severity,
            calculate_score(
                data,
                2,
                severity
            ),
            category
        )
        writer.add_result(result)
        writer.write("")
        writer.write(name,CYAN)
        for item in data:
            writer.write(item)
        writer.write(
            "Severity: "+severity,
            writer.severity_output(severity)
        )
        score+=result.score
    return score
def mac_checks(writer):
    score=0
    checks=[
        (
            "Suspicious Processes",
            ["ps","aux"],
            "Collects running processes.",
            "Review unusual processes.",
            ["ps"],
            1,
            "process"
        ),
        (
            "Hidden Files",
            [
                "find",
                "/tmp",
                "/var/tmp",
                "/Users",
                "-type",
                "f",
                "-name",
                ".*"
            ],
            "Searches hidden files.",
            "Hidden files require review.",
            ["find"],
            1,
            "filesystem"
        ),
        (
            "Network Activity",
            [
                "netstat",
                "-an"
            ],
            "Displays network activity.",
            "Unexpected network activity detected.",
            ["netstat"],
            2,
            "network"
        )
    ]
    results=run_parallel_checks(
        writer,
        checks
    )
    for result in results:
        score+=result.score
    return score
def windows_checks(writer):
    score=0
    checks=[
        (
            "Suspicious Processes",
            [
                "tasklist"
            ],
            "Lists running processes.",
            "Review suspicious processes.",
            ["tasklist"],
            1,
            "process"
        ),
        (
            "Network Activity",
            [
                "netstat",
                "-an"
            ],
            "Displays network connections.",
            "Unexpected connections detected.",
            ["netstat"],
            2,
            "network"
        ),
        (
            "Users and Groups",
            [
                "net",
                "user"
            ],
            "Lists local accounts.",
            "Unexpected accounts detected.",
            ["net"],
            1,
            "account"
        ),
        (
            "Scheduled Tasks",
            [
                "schtasks",
                "/query"
            ],
            "Checks scheduled persistence.",
            "Unexpected scheduled tasks detected.",
            ["schtasks"],
            2,
            "persistence"
        )
    ]
    results=run_parallel_checks(
        writer,
        checks
    )
    for result in results:
        score+=result.score
    return score
def forensic_checks(writer):
    score=0
    checks=[
        (
            "SSH Authorized Keys",
            [
                "bash",
                "-c",
                "find /root /home -name authorized_keys -type f -exec sh -c 'echo === $1 ===;cat $1' _ {} \\; 2>/dev/null"
            ],
            "Checks SSH persistence.",
            "Unknown SSH keys may indicate unauthorized access.",
            ["bash","find"],
            2,
            "persistence"
        ),
        (
            "SUID Files",
            [
                "bash",
                "-c",
                "find / -type f -perm -4000 2>/dev/null"
            ],
            "Checks privileged executables.",
            "Unexpected SUID files require investigation.",
            ["bash","find"],
            2,
            "privilege"
        ),
        (
            "File Capabilities",
            [
                "bash",
                "-c",
                "getcap -r / 2>/dev/null"
            ],
            "Checks Linux capabilities.",
            "Unexpected capabilities may allow privilege escalation.",
            ["bash","getcap"],
            2,
            "privilege"
        ),
        (
            "Systemd Services",
            [
                "systemctl",
                "list-unit-files",
                "--type=service"
            ],
            "Lists installed services.",
            "Unknown services require review.",
            ["systemctl"],
            1,
            "persistence"
        )
    ]
    results=run_parallel_checks(
        writer,
        checks
    )
    for result in results:
        score+=result.score
    return score
def create_baseline(path=BASELINE_FILE):
    baseline={
        "created":str(datetime.now()),
        "hostname":platform.node(),
        "system":platform.system(),
        "files":{}
    }
    locations=[
        "/bin",
        "/usr/bin",
        "/sbin",
        "/usr/sbin"
    ]
    for location in locations:
        if os.path.exists(location):
            for item in safe_walk(location):
                digest=hash_file(item)
                if digest:
                    baseline["files"][item]=digest
    try:
        with open(path,"w",encoding="utf-8") as f:
            json.dump(
                baseline,
                f,
                indent=2
            )
        return True
    except Exception:
        return False
def check_baseline(path=BASELINE_FILE):
    changes=[]
    if not os.path.exists(path):
        return changes
    try:
        with open(path,"r",encoding="utf-8") as f:
            baseline=json.load(f)
    except Exception:
        return changes
    for item,old_hash in baseline.get("files",{}).items():
        if os.path.exists(item):
            new_hash=hash_file(item)
            if new_hash and new_hash!=old_hash:
                changes.append(
                    {
                        "file":item,
                        "old_hash":old_hash,
                        "new_hash":new_hash
                    }
                )
    return changes
def export_json(writer,path,total_score,risk):
    data={
        "generated":str(datetime.now()),
        "system":get_system_info(),
        "score":total_score,
        "risk":risk,
        "results":[
            result.to_dict()
            for result in writer.results
        ]
    }
    try:
        with open(path,"w",encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=2
            )
        return True
    except Exception:
        return False
def export_html(writer,path,total_score,risk):
    try:
        with open(path,"w",encoding="utf-8") as f:
            f.write(
                "<html><head>"
                "<title>h3ktic Report</title>"
                "</head><body>"
            )
            f.write(
                "<h1>System Compromise Report</h1>"
            )
            f.write(
                "<h2>Risk: "+
                html.escape(risk)+
                "</h2>"
            )
            f.write(
                "<h2>Score: "+
                str(total_score)+
                "</h2>"
            )
            f.write(
                "<table border='1'>"
                "<tr>"
                "<th>Name</th>"
                "<th>Severity</th>"
                "<th>Score</th>"
                "</tr>"
            )
            for result in writer.results:
                f.write(
                    "<tr>"
                    "<td>"+
                    html.escape(result.name)+
                    "</td>"
                    "<td>"+
                    html.escape(result.severity)+
                    "</td>"
                    "<td>"+
                    str(result.score)+
                    "</td>"
                    "</tr>"
                )
            f.write(
                "</table>"
            )
            f.write(
                "</body></html>"
            )
        return True
    except Exception:
        return False
def calculate_risk(score):
    if score<20:
        return "Low Risk",GREEN
    if score<50:
        return "Medium Risk",YELLOW
    if score<80:
        return "High Risk",RED
    return "Critical Risk",RED
def parse_arguments():
    parser=argparse.ArgumentParser(
        description=
        "Multi platform system compromise checker with forensic analysis."
    )
    parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Directory for reports."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed execution information."
    )
    parser.add_argument(
        "-d",
        "--deep",
        action="store_true",
        help="Enable deep forensic checks."
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write JSON report."
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Write HTML report."
    )
    parser.add_argument(
        "--baseline",
        choices=[
            "save",
            "check"
        ],
        help="Create or compare system baseline."
    )
    return parser.parse_args()
def display_banner(writer):
    writer.section(
        "Enhanced System Compromise Check"
    )
    info=get_system_info()
    writer.write(
        "Report generated: "+
        str(datetime.now())
    )
    writer.write(
        "Operating System: "+
        info["system"]
    )
    writer.write(
        "Release: "+
        info["release"]
    )
    writer.write(
        "Machine: "+
        info["machine"]
    )
    writer.write(
        "Hostname: "+
        info["hostname"]
    )
    writer.write(
        "Python: "+
        info["python"]
    )
    if info["root"]:
        writer.write(
            "Privileges: root",
            YELLOW
        )
    else:
        writer.write(
            "Privileges: standard user"
        )
    writer.write(
        "This tool identifies indicators requiring investigation."
    )
    writer.write(
        "It does not automatically confirm compromise."
    )
def process_baseline(writer,mode):
    if mode=="save":
        if create_baseline():
            writer.write(
                "Baseline created.",
                GREEN
            )
        else:
            writer.write(
                "Baseline creation failed.",
                RED
            )
        return True
    if mode=="check":
        writer.section(
            "Baseline Comparison"
        )
        changes=check_baseline()
        if not changes:
            writer.write(
                "No baseline changes detected.",
                GREEN
            )
        else:
            for change in changes:
                writer.write(
                    "Changed file: "+
                    change["file"],
                    RED
                )
        return True
    return False
def main():
    args=parse_arguments()
    if not os.path.isdir(args.output):
        try:
            os.makedirs(
                args.output,
                exist_ok=True
            )
        except Exception as e:
            print(
                RED+
                "Unable to create output directory: "+
                str(e)+
                RESET
            )
            sys.exit(1)
    report_file=create_report_filename(
        args.output
    )
    writer=ReportWriter(
        report_file,
        args.verbose
    )
    display_banner(writer)
    if args.baseline:
        process_baseline(
            writer,
            args.baseline
        )
        if args.baseline=="save":
            writer.write(
                "Baseline operation completed.",
                GREEN
            )
            writer.write(
                "Report saved to: "+
                os.path.abspath(report_file),
                CYAN
            )
            return
    total_score=0
    system=get_system_type()
    writer.section(
        "System Checks"
    )
    if system=="linux":
        total_score+=linux_checks(
            writer
        )
    elif system=="darwin":
        total_score+=mac_checks(
            writer
        )
    elif system=="windows":
        total_score+=windows_checks(
            writer
        )
    else:
        writer.write(
            "Unsupported operating system: "+
            system,
            RED
        )
    if args.deep:
        writer.section(
            "Deep Forensic Checks"
        )
        total_score+=forensic_checks(
            writer
        )
    writer.section(
        "System Risk Classification"
    )
    risk,color=calculate_risk(
        total_score
    )
    writer.write(
        "TOTAL SUSPICIOUSNESS SCORE: "+
        str(total_score),
        color
    )
    writer.write(
        "SYSTEM RISK LEVEL: "+
        risk,
        color
    )
    if args.json:
        if export_json(
            writer,
            args.json,
            total_score,
            risk
        ):
            writer.write(
                "JSON report written: "+
                args.json,
                CYAN
            )
        else:
            writer.write(
                "JSON export failed.",
                RED
            )
    if args.html:
        if export_html(
            writer,
            args.html,
            total_score,
            risk
        ):
            writer.write(
                "HTML report written: "+
                args.html,
                CYAN
            )
        else:
            writer.write(
                "HTML export failed.",
                RED
            )
    writer.write(
        "Report saved to: "+
        os.path.abspath(report_file),
        CYAN
    )
    writer.write(
        "Review findings before corrective action."
    )
if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            YELLOW+
            "\nScan interrupted by user."+
            RESET
        )
        sys.exit(130)
    except Exception as e:
        print(
            RED+
            "Fatal error: "+
            str(e)+
            RESET
        )
        sys.exit(1)
