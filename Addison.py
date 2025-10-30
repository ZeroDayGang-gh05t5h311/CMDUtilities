#!/usr/bin/python3
from __future__ import annotations
import argparse
import concurrent.futures
import json
import csv
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import bisect
import string
import random,sys,os,subprocess,ast,operator,platform,re,io
# -------- SAFE CALCULATOR -------- #
class SafeCalc:
    OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.FloorDiv: operator.floordiv,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }
    @staticmethod
    def eval_expr(expr):
        """Safely evaluate a math expression using AST parsing."""
        node = ast.parse(expr, mode="eval").body
        return SafeCalc._eval(node)
    @staticmethod
    def _eval(node):
        if isinstance(node, ast.BinOp):
            left = SafeCalc._eval(node.left)
            right = SafeCalc._eval(node.right)
            return SafeCalc.OPS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp):
            operand = SafeCalc._eval(node.operand)
            return SafeCalc.OPS[type(node.op)](operand)
        elif isinstance(node, ast.Num):  # Python 3.7 and below
            return node.n
        elif isinstance(node, ast.Constant):  # Python 3.8+
            if isinstance(node.value, (int, float)):
                return node.value
            else:
                raise ValueError("Only numbers allowed")
        else:
            raise TypeError(f"Unsupported expression: {ast.dump(node)}")
# -------- MAIN TOOL CLASS -------- #
class tool:
    @staticmethod
    def getInput(ios, arg):
        if ios:  # If ios is True, return as integer
            return int(input(f"{arg}"))
        else:
            return input(f"{arg}")  # Return as string
    @staticmethod
    def cmd(args, capture=False):
        """Run a system command safely with subprocess."""
        try:
            if isinstance(args, str):
                args = args.split()
            if capture:
                result = subprocess.run(args, capture_output=True, text=True, check=True)
                return result.stdout
            else:
                subprocess.run(args, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Command failed: {e}")
    @staticmethod
    def mdir():
        dname = tool.getInput(False, "Directory name please: ")
        tool.cmd(["mkdir", "-p", dname])   # -p avoids crash if dir exists
        print(f"OK, have made a directory called: '{dname}'\nPATH: {os.getcwd()}")
    @staticmethod
    def read(fname):
        try:
            with open(fname, "r") as tmp_var:
                print(tmp_var.read())
        except FileNotFoundError:
            print("File not found!")
    @staticmethod
    def write(fname):
        tmp_data = tool.getInput(False, "> ")
        try:
            with open(fname, "a+") as tmp_var:
                tmp_var.write(tmp_data)
        except FileNotFoundError:
            print("File not found!")
    @staticmethod
    def appendFile():
        apfname = tool.getInput(False, "Filename please.\n$: ")
        tofile = tool.getInput(False, "To add to the file...$: ")
        with open(apfname, "a") as fileOpen:
            fileOpen.write(f"\n{tofile}")
        print("Written to file...")
    @staticmethod
    def sfile(filename, search):
        try:
            result = tool.cmd(["grep", "-i", search, filename], capture=True)
            print(result if result else "No matches found.")
        except Exception:
            print("No matches found.")
    @staticmethod
    def mkpasswd():
        letters = "abcdefghijklmnopqrstuvwxyz"
        numbs = "0123456789"
        special = "!^*£$"
        passwd = random.choice(letters)  # Must start with a letter
        for _ in range(7):  # Target length 8
            randSel = random.randint(0, 2)
            if randSel == 0:
                passwd += random.choice(letters)
            elif randSel == 1:
                passwd += random.choice(numbs)
            else:
                passwd += random.choice(special)
        print(f"Password is: {passwd}\nLength: {len(passwd)}")
        return passwd
    @staticmethod
    def guess():
        print("Ok... guessing game, 5 difficulty levels")
        rdm_diff_select = [[0, 2], [0, 4], [0, 5], [0, 6], [0, 9]]
        tmp = 2
        try:
            tmp = tool.getInput(True, "Please select difficulty 1-5 (default 2): ")
        except ValueError:
            print("Value Error... defaulting to 2")
        player_int = random.randint(*rdm_diff_select[tmp - 1])
        cpu_int = random.randint(*rdm_diff_select[tmp - 1])
        print(f"Your number is: {player_int}.\nComputer's is: {cpu_int}.")
    @staticmethod
    def calc():
        try:
            expr = tool.getInput(False, "Please type a sum, e.g. '1+2*3': ")
            result = SafeCalc.eval_expr(expr)
            print(f"= {result}")
        except Exception as e:
            print(f"Error: {e}")
    @staticmethod
    def local():
        fname = "local_system_information.txt"
        with open(fname, "w") as f:
            f.write(tool.cmd(["w", "-i", "-p"], capture=True) or "")
            f.write(tool.cmd(["who", "-a"], capture=True) or "")
            f.write(tool.cmd(["service", "--status-all"], capture=True) or "")
            f.write(tool.cmd(["netstat", "-tuln"], capture=True) or "")
        print(f"System info written to {fname}")
    @staticmethod
    def osi():
        print("""
6) Application: DNS, HTTP/HTTPS, Email, FTP
5) Presentation: Data representation (HTML,DOC,JPEG,MP3)
4) Session: Inter host communication (TCP,SIP,RTP)
3) Transport: End-to-End (TCP,UDP,TLS)
2) Network: IP, ICMP, OSPF
1) Data Link: Ethernet, 802.11, ARP
0) Physical: Binary transmission (RJ45, DSL, Wi-Fi)
        """)
    @staticmethod
    def ohd():
        tool.cmd(["man", "ascii"])
    @staticmethod
    def wdh():
        domain = tool.getInput(False, "Domain name please (e.g google.com):\n$: ")
        save = tool.getInput(False, "Save to disk? (y/n): ").lower()
        fileName = tool.getInput(False, "Please pick a filename: ")
        if save in ["yes", "y"]:
            with open(fileName, "w") as f:
                f.write(tool.cmd(["whois", domain], capture=True) or "")
                f.write(tool.cmd(["dig", domain], capture=True) or "")
                f.write(tool.cmd(["host", domain], capture=True) or "")
            print(f"Results saved to {fileName}")
        else:
            print(tool.cmd(["whois", domain], capture=True))
            print(tool.cmd(["dig", domain], capture=True))
            print(tool.cmd(["host", domain], capture=True))
    @staticmethod
    def pchk():
        port = tool.getInput(True, "Port Please: ")
        output = tool.cmd(["netstat", "-pnltu"], capture=True)
        if output:
            for line in output.splitlines():
                if f":{port}" in line:
                    print(line)
    @staticmethod
    def lsys():
        system = platform.system()
        def run_capture(cmd):
            try:
                result = subprocess.run(cmd, shell=True, check=True, text=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                return result.stdout
            except subprocess.CalledProcessError as e:
                return f"Error running command '{cmd}':\n{e.output}"
        def append_to_file(header, content):
            with open(output_file, "a") as f:
                f.write(f"{'='*40}\n")
                f.write(f"{header}\n")
                f.write(f"{'-'*40}\n")
                f.write(content + "\n\n")
        # 1. netstat
        append_to_file("Output of netstat -an", run_capture("netstat -an"))
        # 2. ping
        host = "google.com"
        ping_cmd = f"ping -c 4 {host}" if system != "Windows" else f"ping -n 4 {host}"
        append_to_file(f"Output of {ping_cmd}", run_capture(ping_cmd))
        # 3. CPU info
        cpu_cmd = "lscpu" if system != "Windows" else "wmic cpu get name,NumberOfCores,MaxClockSpeed"
        append_to_file(f"Output of {cpu_cmd}", run_capture(cpu_cmd))
        # 4. Memory info
        mem_cmd = "free -h" if system != "Windows" else "systeminfo | findstr /C:\"Total Physical Memory\""
        append_to_file(f"Output of {mem_cmd}", run_capture(mem_cmd))
        # 5. uptime
        uptime_cmd = "uptime" if system != "Windows" else "net stats srv"
        append_to_file(f"Output of {uptime_cmd}", run_capture(uptime_cmd))
        # 6. whoami
        append_to_file("Output of whoami", run_capture("whoami"))
        # 7. sha256sum
        filename_to_hash = "example.txt"  # Change if needed
        hash_cmd = f"sha256sum {filename_to_hash}" if system != "Windows" else f"CertUtil -hashfile {filename_to_hash} SHA256"
        append_to_file(f"Output of {hash_cmd}", run_capture(hash_cmd))
        print(f"System report saved to: {output_file}")
    @staticmethod
    def dirmap():
        from pathlib import Path
        if sys.platform.startswith("win"):
            import string
            start_paths = [f"{d}:/" for d in string.ascii_uppercase if os.path.exists(f"{d}:/")]
        else:
            start_paths = ["/"]
        output_file = "directory_map.txt"
        print(f"[*] Mapping directories from {start_paths} ...")
        with open(output_file, "w", encoding="utf-8") as f:
            for start_path in start_paths:
                base_path = Path(start_path).resolve()
                f.write(f"{base_path}/\n")
                base_path_len = len(base_path.parts)

                for root, dirs, files in os.walk(base_path, topdown=True, followlinks=False):
                    try:
                        current_path = Path(root)
                        rel_parts = current_path.parts[base_path_len:]
                        level = len(rel_parts)
                        indent = "│   " * (level - 1) + ("├── " if level > 0 else "")
                        dir_name = current_path.name if level > 0 else str(current_path)
                        f.write(f"{indent}{dir_name}/\n")

                        subindent = "│   " * level + "├── "
                        for name in files:
                            f.write(f"{subindent}{name}\n")
                    except Exception as e:
                        sys.stderr.write(f"Error accessing {root}: {e}\n")
        print(f"[+] Directory map saved to {output_file}")
    @staticmethod
    def asm_scanner(mode, path):
        """
        mode: "--asm" (path is asm file) or "--bin" (path is binary file to objdump)
        Returns a list of detected issue strings and also prints results (similar to C++ original).
        """
        import concurrent.futures
        from pathlib import Path
        from threading import Lock
        # Prepare pattern groups (translated from C++)
        def get_asm_vuln_patterns():
            return [
                {"name": "Buffer Overflow / Unsafe Memory Operations", "patterns": [
                    re.compile(r"\bstrcpy\b", re.IGNORECASE),
                    re.compile(r"\bstrncpy\b", re.IGNORECASE),
                    re.compile(r"\bstrcat\b", re.IGNORECASE),
                    re.compile(r"\bstrncat\b", re.IGNORECASE),
                    re.compile(r"\bgets\b", re.IGNORECASE),
                    re.compile(r"\bscanf\b", re.IGNORECASE),
                    re.compile(r"\bfscanf\b", re.IGNORECASE),
                    re.compile(r"\bsscanf\b", re.IGNORECASE),
                    re.compile(r"\bmemcpy\b", re.IGNORECASE),
                    re.compile(r"\bmemmove\b", re.IGNORECASE),
                    re.compile(r"\bmovs\b", re.IGNORECASE),
                    re.compile(r"\bstosb\b|\bstosd\b|\bstosw\b", re.IGNORECASE),
                    re.compile(r"\bcmps\b", re.IGNORECASE),
                    re.compile(r"\blods\b|lodsb|lodsw|lodsd", re.IGNORECASE),
                    re.compile(r"\bxor\s+[a-z0-9]+,\s*\[.*\]", re.IGNORECASE),
                    re.compile(r"\badd\s+[a-z0-9]+,\s*\[.*\]", re.IGNORECASE),
                    re.compile(r"\bsub\s+[a-z0-9]+,\s*\[.*\]", re.IGNORECASE),
                ]},
                {"name": "Unsafe Function Call / Library Routines", "patterns": [
                    re.compile(r"\bcall\s+strcpy\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+strncpy\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+strcat\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+strncat\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+gets\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+scanf\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+fscanf\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+sscanf\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+system\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+popen\b", re.IGNORECASE),
                    re.compile(r"\bcall\s+execve\b", re.IGNORECASE),
                ]},
                {"name": "Hardcoded Secrets / Data Strings", "patterns": [
                    re.compile(r"\bdb\s+\".*password.*\"", re.IGNORECASE),
                    re.compile(r"\bdb\s+\".*secret.*\"", re.IGNORECASE),
                    re.compile(r"\bdb\s+\".*key.*\"", re.IGNORECASE),
                    re.compile(r"\bdb\s+\".*token.*\"", re.IGNORECASE),
                    re.compile(r"\bdb\s+\".*credential.*\"", re.IGNORECASE),
                    re.compile(r"\bdata\s+\".*password.*\"", re.IGNORECASE),
                    re.compile(r"\bdata\s+\".*secret.*\"", re.IGNORECASE),
                ]},
                {"name": "Privilege / Permissions / Escalation Instructions", "patterns": [
                    re.compile(r"\biopl\b", re.IGNORECASE),
                    re.compile(r"\bitsl\b", re.IGNORECASE),
                    re.compile(r"\bcli\b", re.IGNORECASE),
                    re.compile(r"\bsti\b", re.IGNORECASE),
                    re.compile(r"\bout\s+", re.IGNORECASE),
                    re.compile(r"\bin\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x80\b.*\bsetuid\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x80\b.*\bsetgid\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x80\b.*\bchmod\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x80\b.*\bchown\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x80\b.*\brwx\b", re.IGNORECASE),
                ]},
                {"name": "Suspicious Syscalls / Interrupts", "patterns": [
                    re.compile(r"\bint\s+0x80\b", re.IGNORECASE),
                    re.compile(r"\bsyscall\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x2e\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x81\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x82\b", re.IGNORECASE),
                    re.compile(r"\bint\s+0x90\b", re.IGNORECASE),
                    re.compile(r"\btrap\b", re.IGNORECASE),
                    re.compile(r"\beret\b", re.IGNORECASE),
                ]},
                {"name": "Control Flow / Return Oriented Programming (ROP) / Jump Gadgets", "patterns": [
                    re.compile(r"\bjmp\s+[a-zA-Z0-9_]+\b", re.IGNORECASE),
                    re.compile(r"\bjmp\s*\[.*\]", re.IGNORECASE),
                    re.compile(r"\bcall\s*\[.*\]", re.IGNORECASE),
                    re.compile(r"\bpush\s+[^\n]*; ret\b", re.IGNORECASE),
                    re.compile(r"\bpop\s+[^\n]*; ret\b", re.IGNORECASE),
                    re.compile(r"\bret\b", re.IGNORECASE),
                    re.compile(r"\bleave\b", re.IGNORECASE),
                ]},
                {"name": "Format String / Debug / Info Leakage", "patterns": [
                    re.compile(r"\bodbc\b|\bprintf\b|\bsprintf\b|\bvsprintf\b", re.IGNORECASE),
                    re.compile(r"\bprintf\b", re.IGNORECASE),
                    re.compile(r"\bsprintf\b", re.IGNORECASE),
                    re.compile(r"\bvsprintf\b", re.IGNORECASE),
                    re.compile(r"\bwprintf\b", re.IGNORECASE),
                    re.compile(r"\bwprintf_s\b", re.IGNORECASE),
                    re.compile(r"\bdebug\b", re.IGNORECASE),
                    re.compile(r"\bprintk\b", re.IGNORECASE),
                ]},
                {"name": "Arithmetic / Overflow Risks", "patterns": [
                    re.compile(r"\badd\b", re.IGNORECASE),
                    re.compile(r"\bsub\b", re.IGNORECASE),
                    re.compile(r"\bmul\b", re.IGNORECASE),
                    re.compile(r"\bdiv\b", re.IGNORECASE),
                    re.compile(r"\bimul\b", re.IGNORECASE),
                    re.compile(r"\bdivl\b", re.IGNORECASE),
                    re.compile(r"\bjo\b|\bjc\b|\bbe\b|\bja\b|\bjb\b|\bjl\b|\bjg\b", re.IGNORECASE),
                ]},
            ]
        pattern_groups = get_asm_vuln_patterns()
        # Exec objdump if requested
        asm_text = ""
        if mode == "--asm":
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    asm_text = fh.read()
            except Exception as e:
                print(f"Error opening asm file: {path}: {e}", file=sys.stderr)
                return []
        elif mode == "--bin":
            try:
                proc = subprocess.run(["objdump", "-d", path], capture_output=True, text=True, check=True)
                asm_text = proc.stdout
            except Exception as e:
                print(f"Error running objdump on {path}: {e}", file=sys.stderr)
                return []
        else:
            print("Unknown mode. Use --asm or --bin", file=sys.stderr)
            return []
        # Scan lines in parallel-ish: spawn worker per line (ThreadPool)
        issues = []
        seen_issues = set()
        seen_lock = Lock()
        lines = asm_text.splitlines()
        # Worker function
        def worker(line_index_line):
            index, line = line_index_line
            local = []
            # Normalize line: collapse multiple spaces into single space
            normalized_line = re.sub(r"\s+", " ", line)
            for group in pattern_groups:
                gname = group["name"]
                for pat in group["patterns"]:
                    try:
                        if pat.search(normalized_line):
                            identifier = f"{gname}:{index}:{normalized_line}"
                            with seen_lock:
                                if identifier in seen_issues:
                                    matched = False
                                else:
                                    seen_issues.add(identifier)
                                    matched = True
                            if matched:
                                local.append(f"[{gname}] {path}:{index}: {line}")
                            # once matched by a pattern in the group, don't repeat same group for same line
                            break
                    except re.error:
                        # skip invalid pattern (shouldn't happen)
                        continue
            return local
        # Use ThreadPoolExecutor to parallelize checking
        max_workers = min(32, (os.cpu_count() or 1) * 5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = list(executor.map(worker, enumerate(lines, start=1)))
            for fr in futures:
                if fr:
                    issues.extend(fr)
        # Print results roughly like original
        if not issues:
            print(" No potential vulnerabilities found.\n")
        else:
            print(" Potential vulnerabilities detected:\n")
            for issue in issues:
                print(issue)
        return issues
    @staticmethod
    def cves():
        LANG_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.java': 'java',
    '.sh': 'shell',
    '.bash': 'shell',
}
# -------------------------
# Full pattern lists
# (Copied from user's original lists)
# -------------------------
# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    r"(?i)select\s+\*\s+from\s+\w+",
    r"(?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s+\(.*\)",
    r"(?i)update\s+\w+\s+set\s+.*\s+where\s+.*",
    r"(?i)drop\s+table\s+\w+",
    r"(?i)union\s+select\s+.*",
    r"(?i)and\s+1\s*=\s*1",
    r"(?i)or\s+1\s*=\s*1",
    r"(?i)select\s+from\s+information_schema.tables",
    r"(?i)select\s+from\s+mysql.*user",
    r"(?i)select\s+from\s+pg_catalog.*pg_user",
    r"(?i)select\s+from\s+sys\.databases",
    r"(?i)select\s+from\s+sqlite_master",
    r"(?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+",
    r"(?i)cursor\.execute\s*\(\s*.*\)",
    r"(?i)prepareStatement\s*\(",
    r"(?i)WHERE\s+1=1\s+--",
    r"(?i)--\s*$|#\s*$",
    r"(?i)UNION\s+ALL\s+SELECT",
    r"(?i)CAST\(.+AS\s+VARCHAR",
]
# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    r'(?i)document\.write\s*\(',
    r'(?i)eval\((.*)\)\s*;',
    r'(?i)innerHTML\s*=\s*',
    r'(?i)window\.location\s*=',
    r'(?i)location\.href\s*=',
    r'(?i)alert\s*\(',
    r'(?i)confirm\s*\(',
    r'(?i)document\.cookie',
    r'(?i)eval\s*\(\s*["\'].*["\']\s*\)',
    r"(?i)response\.write\(",
    r"(?i)res\.send\(",
    r"(?i)innerText\s*=",
    r"(?i)document\.createElement\(['\"]script['\"]\)",
    r"(?i)setAttribute\(\s*['\"]on\w+['\"]\s*,",
    r"(?i)dangerouslySetInnerHTML",
    r"(?i)style\.cssText\s*=",
    r"(?i)location\.replace\s*\(",
    r"(?i)res\.end\s*\(",
]
# Command Injection Patterns
COMMAND_INJECTION_PATTERNS = [
    r"(?i)system\s*\(",
    r"(?i)popen\s*\(",
    r"(?i)exec\s*\(",
    r"(?i)Runtime\.getRuntime\s*\(\)\.exec\s*\(",
    r"(?i)subprocess\.(call|Popen)\s*\(",
    r"(?i)child_process\.exec\s*\(",
    r"(?i)nc\s+-e\s+",
    r"(?i)\$\([^\)]*\)",
    r"(?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\)",
    r"(?i)shell=True",
    r"(?i)cmd\.exe\s*/c",
    r"(?i)system\([^,]+;",
    r"(?i)exec\([^,]+\+",
    r"(?i)popen\([^,]+\+",
    r"(?i)ProcessBuilder\s*\(.+builder\.command\(",
    r"(?i)Runtime\.exec\(.+\+",
    r"(?i)popen2|popen3",
    r"(?i)subprocess\.(call|check_output)\s*\(.*\+",
]
# Path Traversal Patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"(\.\./){2,}",
    r"(?i)(c:|/)[^:]+/",
    r"(?i)file://",
    r"(?i)open\s*\(\s*\"(\.\./|/)[^\"]+\"",
    r"(?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\"",
    r"(?i)normalizePath\(|path\.normalize\(",
    r"(?i)realpath\(|os\.realpath\(",
    r"(?i)\.\.\\",
    r"(?i)zipfile\.ZipFile\(|tarfile\.open\(",
    r"(?i)upload_tmp_dir|tmp_name",
    r"(?i)save_path\s*=",
    r"(?i)path\.join\([^,]+,\s*\.\.",
    r"(?i)filename\s*=\s*request\.",
    r"(?i)Content-Disposition:\s*filename=",
]
# Insecure Deserialization Patterns
INSECURE_DESERIALIZATION_PATTERNS = [
    r"(?i)pickle\.load\s*\(",
    r"(?i)unserialize\s*\(",
    r"(?i)ObjectInputStream\s*\(",
    r"(?i)deserialize\s*\(",
    r"(?i)json\.parse\s*\(",
    r"(?i)XMLDecoder\s*\(",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)yaml\.load\s*\(",
    r"(?i)Marshal\.load\s*\(",
    r"(?i)Marshal\.restore\s*\(",
    r"(?i)eval\(.+base64_decode\(",
    r"(?i)gob\.NewDecoder\(|encoding/gob",
    r"(?i)serde_json::from_str\(",
    r"(?i)perl\s+Storable::thaw",
    r"(?i)apache\.commons\.collections",
    r"(?i)readObject\(|writeReplace\(",
    r"(?i)readObject\s*\(",
    r"(?i)writeObject\s*\(",
    r"(?i)ObjectInputStream\.resolveClass",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)Gson\.fromJson\s*\(",
]
# Buffer Overflow Patterns
BUFFER_OVERFLOW_PATTERNS = [
    r"(?i)strcpy\s*\(\s*\w+,\s*\w+\)",
    r"(?i)strcat\s*\(\s*\w+,\s*\w+\)",
    r"(?i)gets\s*\(",
    r"(?i)scanf\s*\(",
    r"(?i)memcpy\s*\(",
    r"(?i)fgets\s*\(",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)yaml\.load\s*\(",
    r"(?i)Marshal\.load\s*\(",
    r"(?i)Marshal\.restore\s*\(",
    r"(?i)eval\(.+base64_decode\(",
    r"(?i)gob\.NewDecoder\(|encoding/gob",
    r"(?i)serde_json::from_str\(",
    r"(?i)perl\s+Storable::thaw",
    r"(?i)apache\.commons\.collections",
    r"(?i)readObject\(|writeReplace\(",
    r"(?i)readObject\s*\(",
    r"(?i)writeObject\s*\(",
    r"(?i)ObjectInputStream\.resolveClass",
    r"(?i)XStream\.fromXML\s*\(",
    r"(?i)Gson\.fromJson\s*\(",
    r"(?i)malloc\s*\(|(?i)calloc\s*\(",
    r"(?i)stack_exec|mprotect\s*\(",
    r"(?i)memset\(.+0x00",
]
# Cross-Site Request Forgery (CSRF) Patterns
CSRF_PATTERNS = [
    r"(?i)document\.location\.href\s*=\s*['\"]\S+['\"]",
    r"(?i)form\s+action\s*=\s*['\"]\S+['\"]",
    r"(?i)window\.location\s*=\s*['\"]\S+['\"]",
    r"(?i)\$\('[^']+'\)\.submit\s*\(",
    r"(?i)post\s+method\s*=\s*['\"]\S+['\"]",
    r"(?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf",
    r"(?i)X-CSRF-Token",
    r"(?i)SameSite=None",
    r"(?i)document\.forms\[[0-9]+\]\.submit",
    r"(?i)action\s*=\s*\"/external",
    r"(?i)autofill",
]
# Improper Authentication Patterns
IMPROPER_AUTHENTICATION_PATTERNS = [
    r"(?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"]",
    r"(?i)request\.cookies\s*\['session_id'\]",
    r"(?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"]",
    r"(?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",
    r"(?i)request\.headers\s*\['Authorization'\]",
    r"(?i)password\s*=\s*['\"][^'\"]{1,}['\"]",
    r"(?i)api_key\s*=\s*['\"][A-Za-z0-9\-_]+['\"]",
    r"(?i)hardcoded_secret|hardcoded_key|private_key\s*=",
    r"(?i)Basic\s+[A-Za-z0-9=]+",
    r"(?i)set_cookie\(|cookie\.set\(",
    r"(?i)session\.(start|destroy)",
    r"(?i)bcrypt\.hashpw\(|password_hash\(",
    r"(?i)compare_digest\(|hmac\.compare_digest\(",
    r"(?i)token_expiry|exp\s*:",
    r"(?i)Authorization\s*:\s*Bearer",
]
# Insecure API Patterns
INSECURE_API_PATTERNS = [
    r"(?i)/api/v[0-9]+/users",
    r"(?i)/api/v[0-9]+/admin",
    r"(?i)/api/v[0-9]+/token",
    r"(?i)/api/v[0-9]+/password",
    r"(?i)/api/v[0-9]+/login",
    r"(?i)/internal/|/private/|/debug/",
    r"(?i)swagger.json|api-docs|/v2/api-docs",
    r"(?i)X-Forwarded-For",
    r"(?i)introspect|.well-known/openid-configuration",
    r"(?i)graphql",
    r"(?i)rate_limit|throttle",
    r"(?i)Authorization\s*:\s*Bearer # token leakage in logs/header",
]
# Insecure Cryptographic Practices Patterns
INSECURE_CRYPTOGRAPHIC_PATTERNS = [
    r"(?i)MD5\s*\(",
    r"(?i)SHA1\s*\(",
    r"(?i)base64\s*\(",
    r"(?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"]",
    r"(?i)AES-ECB|AES128-ECB|ECB_MODE",
    r"(?i)openssl\s+enc\s+-aes-128-cbc",
    r"(?i)RSA_padding\(|RSA_NO_PADDING",
    r"(?i)SSLv3|ssl3",
    r"(?i)RC4|DES|3DES|EXPORT",
    r"(?i)hardcoded_key|hardcoded_password|private_key.*=",
    r"(?i)PBKDF2|bcrypt|scrypt",
    r"(?i)iteration_count\s*=\s*\d{1,4}",
    r"(?i)random\.random\(|Math\.random\(",
    r"(?i)secure_random|SystemRandom",
    r"(?i)HMAC-SHA1",
    r"(?i)cryptography\.hazmat|from\s+Crypto\.",
]
# Race Condition Patterns
RACE_CONDITION_PATTERNS = [
    r"(?i)pthread_mutex_lock\s*\(",
    r"(?i)pthread_mutex_unlock\s*\(",
    r"(?i)fsync\s*\(",
    r"(?i)wait\s*\(",
    r"(?i)open\([^,]+,\s*O_CREAT\|O_EXCL",
    r"(?i)rename\(",
    r"(?i)stat\(|lstat\(",
    r"(?i)mktemp\s*\(",
    r"(?i)lockf\s*\(",
    r"(?i)sem_wait|sem_post",
    r"(?i)volatile\s+",
    r"(?i)atomic_compare_exchange",
    r"(?i)nsync|pthread_create",
]
# Privilege Escalation Patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    r"(?i)sudo\s+",
    r"(?i)chmod\s+777\s+",
    r"(?i)chown\s+",
    r"(?i)setuid\(|setgid\(|seteuid\(|setegid\(",
    r"(?i)cap_set_file|cap_get_proc",
    r"(?i)passwd\s+",
    r"(?i)/etc/shadow|/etc/passwd",
    r"(?i)su\s+-",
    r"(?i)mount\s+-o\s+",
    r"(?i)docker\s+run\s+--privileged",
    r"(?i)iptables\s+",
    r"(?i)chroot\s*\(",
]
# LANGUAGE -> patterns
LANGUAGE_PATTERNS = {
    'python': SQL_INJECTION_PATTERNS + XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_CRYPTOGRAPHIC_PATTERNS,
    'javascript': XSS_PATTERNS + COMMAND_INJECTION_PATTERNS + INSECURE_API_PATTERNS,
    'c': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS + PATH_TRAVERSAL_PATTERNS,
    'cpp': SQL_INJECTION_PATTERNS + COMMAND_INJECTION_PATTERNS + BUFFER_OVERFLOW_PATTERNS + PATH_TRAVERSAL_PATTERNS,
    'java': SQL_INJECTION_PATTERNS + INSECURE_DESERIALIZATION_PATTERNS + IMPROPER_AUTHENTICATION_PATTERNS,
    'shell': COMMAND_INJECTION_PATTERNS + PRIVILEGE_ESCALATION_PATTERNS,
}
# -------------------------
# Defaults
# -------------------------
DEFAULT_IGNORED_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', '.idea', '.gradle'}
# -------------------------
# Utilities
# -------------------------
def load_custom_patterns(config_file: Path) -> Dict[str, List[str]]:
    """Load custom patterns JSON. Expect format: { "python": ["pattern1", ...], "all": [...] }"""
    try:
        with open(config_file, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("Custom patterns JSON must be an object/dictionary.")
            return {k.lower(): v for k, v in data.items()}
    except Exception as e:
        print(f"[!] Error loading custom patterns: {e}", file=sys.stderr)
        return {}

def is_text_file(path: Path, max_bytes: int = 2048, printable_threshold: float = 0.75) -> bool:
    """
    Rudimentary text file detection: read small chunk and check for null bytes and printable ratio.
    """
    try:
        with open(path, 'rb') as fh:
            chunk = fh.read(max_bytes)
            if not chunk:
                return True
            if b'\x00' in chunk:
                return False
            printable = bytes(string.printable, 'ascii')
            printable_count = sum(1 for b in chunk if b in printable)
            ratio = printable_count / len(chunk)
            return ratio >= printable_threshold
    except Exception:
        return False
def compile_patterns(pattern_list: List[str]) -> List[re.Pattern]:
    """Compile a list of regex strings into compiled patterns with IGNORECASE and MULTILINE flags."""
    compiled: List[re.Pattern] = []
    for p in pattern_list:
        if not isinstance(p, str):
            continue
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
        except re.error:
            compiled.append(re.compile(re.escape(p), re.IGNORECASE | re.MULTILINE))
    return compiled
# -------------------------
# Tokenizers: remove/blank comments & strings while preserving offsets
# -------------------------
# Approach: find all comment/string spans, then blank them (replace chars by spaces except keep newlines)
# so offsets of remaining content line up with original text for accurate line mapping.

def blank_span(text: str, start: int, end: int) -> None:
    """Helper to blank a slice in a bytearray-like list preserving newlines."""
    # This is implemented inside tokenizer where we operate on a list of characters
def remove_comments_and_strings_preserve_offsets(text: str, lang: str) -> str:
    """
    Return a copy of text with comments and string literals replaced by spaces (newlines preserved)
    so that offsets remain aligned with original text.
    Language-specific handling for python, javascript, c/cpp/java, shell.
    """
    # Work on a mutable list of characters to replace ranges in-place
    chars = list(text)
    full_len = len(chars)
    # Generic regex pieces to find strings and comments
    # Python: single, double, triple-single, triple-double strings, and # comments
    if lang == 'python':
        # triple-quoted or single/double quoted strings, also f-strings, r-strings etc (approx)
        # Note: (?s) enables DOTALL so triple quotes span lines
        pattern = re.compile(
            r"""(?P<triple_single>'''(?:.|[\r\n])*?''')|
                (?P<triple_double>""" + '"""' + r"""(?:.|[\r\n])*?""" + '"""' + r""")|
                (?P<single>'(?:\\.|[^'\\\n])*')|
                (?P<double>"(?:\\.|[^"\\\n])*")|
                (?P<comment>\#.*?$)""",
            re.MULTILINE | re.DOTALL | re.VERBOSE
        )
    elif lang == 'javascript' or lang == 'shell':
        # JS: single, double, backtick strings; // comments; /* */ comments
        # Shell: single/double/backticked strings, # comments (single-line)
        if lang == 'javascript':
            comment_single = r"//.*?$"
            comment_multi = r"/\*[\s\S]*?\*/"
        else:
            # shell
            comment_single = r"#.*?$"
            comment_multi = r""  # typically no multiline /* */ in shell
        pattern = re.compile(
            r"(?P<backtick>`(?:\\.|[^`\\\n])*`)|"
            r"(?P<single>'(?:\\.|[^'\\\n])*')|"
            r'(?P<double>"(?:\\.|[^"\\\n])*")|'
            + (f"(?P<comment1>{comment_single})|" if comment_single else "") +
            (f"(?P<comment2>{comment_multi})" if comment_multi else ""),
            re.MULTILINE | re.DOTALL
        )
    elif lang in ('c', 'cpp', 'java'):
        # C/CPP/Java: single/double quoted char/string, // comments, /* */ comments
        pattern = re.compile(
            r"(?P<char>'(?:\\.|[^'\\\n])*')|"
            r'(?P<double>"(?:\\.|[^"\\\n])*")|'
            r"(?P<comment1>//.*?$)|(?P<comment2>/\*[\s\S]*?\*/)",
            re.MULTILINE | re.DOTALL
        )
    else:
        # unknown language: fallback to remove basic comment patterns and quotes
        pattern = re.compile(
            r"(?P<single>'(?:\\.|[^'\\\n])*')|(?P<double>\"(?:\\.|[^\"\\\n])*\")|(?P<comment>\#.*?$)",
            re.MULTILINE | re.DOTALL
        )
    for m in pattern.finditer(text):
        s, e = m.start(), m.end()
        # replace all non-newlines in this span with spaces
        for i in range(s, e):
            if chars[i] != '\n':
                chars[i] = ' '
    return ''.join(chars)
# -------------------------
# Matching and line mapping
# -------------------------
def find_matches_in_text(text: str, compiled_patterns: List[re.Pattern], path: Path, lang: str) -> List[Dict[str, Any]]:
    """
    Find matches while ignoring content inside comments/strings for the given language.
    We blank comments/strings (preserving newlines), then run patterns.
    Map match offsets back to line numbers via bisect on line start offsets.
    """
    matches: List[Dict[str, Any]] = []
    if not compiled_patterns:
        return matches
    if text is None:
        return matches
    # Create a version of text with comments/strings blanked (same length, newlines preserved)
    cleaned = remove_comments_and_strings_preserve_offsets(text, lang)
    # Pre-split original text to compute line offsets (use original text to preserve original snippets)
    lines = text.splitlines()
    offsets: List[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1  # +1 represents newline char length
    if not offsets:
        offsets = [0]
        lines = ['']
    def offset_to_lineno(offset: int) -> int:
        idx = bisect.bisect_right(offsets, offset) - 1
        if idx < 0:
            idx = 0
        return idx + 1
    for pat in compiled_patterns:
        for m in pat.finditer(cleaned):
            try:
                start = m.start()
                line_no = offset_to_lineno(start)
                line_idx = max(0, min(line_no - 1, len(lines) - 1))
                snippet = lines[line_idx].strip()
                matches.append({
                    "file": str(path),
                    "line": line_no,
                    "pattern": pat.pattern,
                    "match_text": (m.group(0)[:300] if m.group(0) is not None else ""),
                    "snippet": snippet
                })
            except Exception:
                matches.append({
                    "file": str(path),
                    "line": 0,
                    "pattern": pat.pattern,
                    "match_text": "",
                    "snippet": "Error mapping match to line"
                })
    return matches
# -------------------------
# Per-file detection and scanning
# -------------------------
def detect_injections_in_file(path: Path, compiled_by_lang: Dict[str, List[re.Pattern]],
                              default_patterns: List[re.Pattern], min_size: int, max_size: int,
                              ignore_exts: List[str]) -> List[Dict[str, Any]]:
    try:
        suffix = path.suffix.lower()
        if suffix in ignore_exts:
            return []
        stat = path.stat()
        if stat.st_size < min_size or (max_size > 0 and stat.st_size > max_size):
            return []
    except Exception:
        return []
    if not is_text_file(path):
        return []
    lang = LANG_EXTENSIONS.get(path.suffix.lower())
    compiled_patterns: List[re.Pattern] = []
    if lang:
        compiled_patterns.extend(compiled_by_lang.get(lang, []))
    compiled_patterns.extend(default_patterns)
    if not compiled_patterns:
        return []
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        return [{"file": str(path), "line": 0, "pattern": "ERROR_READING", "match_text": "", "snippet": f"Error reading file: {e}"}]
    return find_matches_in_text(text, compiled_patterns, path, lang or "")
def scan_directory_for_injections(root_dir: Path, compiled_by_lang: Dict[str, List[re.Pattern]],
                                  default_patterns: List[re.Pattern], threads: int,
                                  min_size: int, max_size: int, ignore_exts: List[str],
                                  ignore_dirs: List[str]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for p in root_dir.rglob("*"):
            try:
                if p.is_file():
                    parts = {part.lower() for part in p.parts}
                    if any(d.lower() in parts for d in ignore_dirs):
                        continue
                    futures.append(ex.submit(detect_injections_in_file, p, compiled_by_lang, default_patterns, min_size, max_size, ignore_exts))
            except Exception:
                continue
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    issues.extend(res)
            except Exception:
                continue
    # Deduplicate by (file, line, pattern, match_text_excerpt)
    seen = set()
    unique = []
    for ii in issues:
        key = (ii.get("file"), ii.get("line"), ii.get("pattern"), (ii.get("match_text") or "")[:80])
        if key not in seen:
            seen.add(key)
            unique.append(ii)
    return unique
# -------------------------
# Save results
# -------------------------
def save_results(issues: List[Dict[str, Any]], output_file: Path, file_format: str) -> None:
    output_file = output_file.resolve()
    if file_format == "json":
        with open(output_file, "w", encoding='utf-8') as fh:
            json.dump(issues, fh, indent=2, ensure_ascii=False)
    elif file_format == "csv":
        with open(output_file, "w", newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(["File", "Line", "Pattern", "Match", "Snippet"])
            for it in issues:
                writer.writerow([it.get("file"), it.get("line"), it.get("pattern"), it.get("match_text"), it.get("snippet")])
    print(f"Results saved to {output_file}")
# -------------------------
# Build compiled sets
# -------------------------
def build_compiled_pattern_sets(custom_patterns: Dict[str, List[str]]) -> Tuple[Dict[str, List[re.Pattern]], List[re.Pattern]]:
    compiled_by_lang: Dict[str, List[re.Pattern]] = {}
    for lang, pats in LANGUAGE_PATTERNS.items():
        compiled_by_lang[lang] = compile_patterns(pats)
    default_patterns: List[re.Pattern] = []
    if custom_patterns:
        for k, v in custom_patterns.items():
            if not isinstance(v, list):
                continue
            k_l = k.lower()
            if k_l == "all":
                default_patterns.extend(compile_patterns([p for p in v if isinstance(p, str)]))
            else:
                compiled_by_lang.setdefault(k_l, [])
                compiled_by_lang[k_l].extend(compile_patterns([p for p in v if isinstance(p, str)]))
    return compiled_by_lang, default_patterns
# -------------------------
# Arg parsing
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Improved static scanner for potential vulnerabilities.")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--config", help="Custom pattern configuration file (JSON)", default=None)
    parser.add_argument("--output", help="Output file name (without extension)", default="vulnerabilities_report")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads")
    parser.add_argument("--ignore-ext", nargs="*", default=[], help="File extensions to ignore (e.g. .png .jpg)")
    parser.add_argument("--ignore-dir", nargs="*", default=[], help="Directory names to ignore (e.g. node_modules .git)")
    parser.add_argument("--min-size", type=int, default=0, help="Minimum file size in bytes to scan")
    parser.add_argument("--max-size", type=int, default=5_000_000, help="Maximum file size in bytes to scan (0 for no limit)")
    return parser.parse_args()
def cves_init():
    args = parse_args()
    root = Path(args.directory)
    if not root.exists() or not root.is_dir():
        print(f"[!] Directory not found: {root}", file=sys.stderr)
        return
    custom = {}
    if args.config:
        custom = load_custom_patterns(Path(args.config))
    compiled_by_lang, default_patterns = build_compiled_pattern_sets(custom)
    # Normalize ignore lists
    ignore_exts = {ext.lower() if ext.startswith('.') else f".{ext.lower()}" for ext in args.ignore_ext}
    ignore_dirs = set([d.lower() for d in args.ignore_dir] + list(DEFAULT_IGNORED_DIRS))
    issues = scan_directory_for_injections(root, compiled_by_lang, default_patterns, args.threads,
                                          args.min_size, args.max_size, list(ignore_exts), list(ignore_dirs))
    if not issues:
        print(" <| No potential vulnerabilities found.")
    else:
        print("<| Potential vulnerabilities detected:\n")
        for it in issues:
            print(f"{it['file']}:{it['line']}  -- {it['pattern']}  -- {it['snippet']}")
        out_path = Path(f"{args.output}.{args.format}")
        save_results(issues, out_path, args.format)
cmds = [
    "help: this help list.",
    "mdir: makes a directory.",
    "read: opens and reads a file.",
    "write: writes to a file.",
    "append: appends to a file.",
    "sfile: search a file.",
    "mkpasswd: makes a random password.",
    "guess: runs a guessing game.",
    "calc: a simple calculator.",
    "local: prints local system information.",
    "osi: displays OSI model info.",
    "ohd: displays ASCII conversions.",
    "wdh: whois/dig/host lookup.",
    "pchk: checks services on a port.", 
    "lsys: runs various system commands and appends their outputs to a file ",
    "dirmap: maps a directory tree of the whole filesystem and put's it in a file(code not implemented).",
    "ascan: assembly scanner(.asm|binary files files).",
    "cves: static vulnerabilities scanner (JavaScript/BASH/C/C++/python) + hard-coded credentials etc."
    ]
def icmd():
    print("Hi, welcome to the console. Type 'help' for options.")
    tmp = tool.getInput(False, "> ")
    if tmp == "exit":
        return "exit"
    elif tmp == "help":
        for each in cmds:
            print(each)
    elif tmp == "mdir":
            tool.mdir()
    elif tmp == "read":
        tool.read(tool.getInput(False, "Filename:\n> "))
    elif tmp == "write":
        tool.write(tool.getInput(False, "Filename:\n> "))
    elif tmp == "append":
        tool.appendFile()
    elif tmp == "sfile":
        fn = tool.getInput(False,"Filename: ")
        s = tool.getInput(False,"Search String: ")
        tool.sfile(fn, s)
    elif tmp == "mkpasswd":
        tool.mkpasswd()
    elif tmp == "guess":
        tool.guess()
    elif tmp == "calc":
        tool.calc()
    elif tmp == "local":
        tool.local()
    elif tmp == "osi":
        tool.osi()
    elif tmp == "ohd":
        tool.ohd()
    elif tmp == "wdh":
        tool.wdh()
    elif tmp == "pchk":
        tool.pchk()
    elif tmp == "lsys":
        tool.lsys()
    elif tmp == "dirmap":
        tool.dirmap()
    elif tmp == "ascan":
        mode = tool.getInput(False, "Mode (--asm or --bin):\n$: ").strip()
        path = tool.getInput(False, "Path to file:\n$: ").strip()
        try:
            tool.asm_scanner(mode, path)
        except Exception as e:
            print(f"Error running asm_scanner: {e}")
        return " "
    elif tmp == "cves":
        tool.cves()
# -------- MAIN LOOP -------- #
tmp = ""
while tmp != "exit":
    tmp = icmd()
