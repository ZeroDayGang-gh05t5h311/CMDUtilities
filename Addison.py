#!/usr/bin/python3
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
        "ascan: assembly scanner(.asm|binary files files)."
    ]
    @staticmethod
    def icmd():
        print("Hi, welcome to the console. Type 'help' for options.")
        tmp = tool.getInput(False, "> ")
        if tmp == "exit":
            return "exit"
        elif tmp == "help":
            for each in tool.cmds:
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
# -------- MAIN LOOP -------- #
tmp = ""
while tmp != "exit":
    tmp = tool.icmd()
