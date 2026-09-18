/*Common Usage Examples
Quick System Check
./portpeep --once --terminal
Continuous Monitoring
./portpeep --continuous --terminal
Monitor for 10 Minutes
./portpeep --continuous --duration 600 --terminal
Create Baseline
./portpeep --learn
Export Report
./portpeep \
--once \
--terminal \
--export-json report.json \
--export-csv report.csv
Files Created
baseline.json */
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <thread>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <numeric>
#include <cmath>
#include <array>
#include <cerrno>
#include <cstring>
#include <unistd.h>
using namespace std;
const int RATE_LIMIT_SECONDS=60;
const int MAX_WORKERS=max(2u,thread::hardware_concurrency()*2);
const string BASELINE_FILE="baseline.json";
const size_t MAX_BASELINE_ENTRIES=10000;
const int FREQ_WINDOW=60;
const int FREQ_THRESHOLD=20;
const int BEACON_MIN_SAMPLES=5;
const double BEACON_VARIANCE_THRESHOLD=2.0;
unordered_set<int> SUSPICIOUS_PORTS={
4444,
5555,
6666,
1337,
9001
};
double now_time()
{
return chrono::duration<double>(
chrono::system_clock::now().time_since_epoch()
).count();
}
string trim_string(const string& input)
{
size_t start=input.find_first_not_of(" \t\r\n");
if(start==string::npos)
return "";
size_t end=input.find_last_not_of(" \t\r\n");
return input.substr(start,end-start+1);
}
string json_escape(const string& input)
{
string output;
output.reserve(input.size()+16);
for(char c:input)
{
switch(c)
{
case '"':
output+="\\\"";
break;
case '\\':
output+="\\\\";
break;
case '\n':
output+="\\n";
break;
case '\r':
output+="\\r";
break;
case '\t':
output+="\\t";
break;
default:
output+=c;
}
}
return output;
}
vector<string> run_command(const string& cmd)
{
vector<string> lines;
FILE* pipe=popen(cmd.c_str(),"r");
if(!pipe)
return lines;
array<char,4096> buffer{};
while(fgets(buffer.data(),static_cast<int>(buffer.size()),pipe))
{
lines.emplace_back(trim_string(buffer.data()));
}
if(pclose(pipe)==-1)
{
lines.clear();
}
return lines;
}
bool is_ephemeral(int port)
{
return port>=32768&&port<=60999;
}
bool is_local_ip(const string& ip)
{
return ip=="127.0.0.1"||
ip=="::1"||
ip.rfind("127.",0)==0;
}
bool parse_port(const string& value,int& port)
{
if(value.empty())
return false;
for(char c:value)
{
if(!isdigit(static_cast<unsigned char>(c)))
return false;
}
try
{
port=stoi(value);
return port>0&&port<=65535;
}
catch(...)
{
return false;
}
}
string get_process_name(int pid)
{
if(pid<=0)
return "unknown";
string cmd=
"ps -p "+
to_string(pid)+
" -o comm= 2>/dev/null";
auto out=run_command(cmd);
if(!out.empty())
return out[0];
return "unknown";
}
string get_process_cmd(int pid)
{
if(pid<=0)
return "unknown";
string cmd=
"ps -p "+
to_string(pid)+
" -o args= 2>/dev/null";
auto out=run_command(cmd);
if(!out.empty())
return out[0];
return "unknown";
}
string get_process_exe(int pid)
{
if(pid<=0)
return "unknown";
string path=
"/proc/"+
to_string(pid)+
"/exe";
vector<char> buffer(4096);
ssize_t len=
readlink(
path.c_str(),
buffer.data(),
buffer.size()-1
);
if(len<=0)
return "unknown";
buffer[len]='\0';
return string(buffer.data());
}
class NetworkMonitor
{
public:
bool learn;
bool terminal_output;
string export_csv;
string export_json;
vector<tuple<double,string,string>> alerts;
unordered_map<string,double> alert_cache;
unordered_map<int,string> proc_cache;
mutex mtx;
unordered_set<int> ALLOWED_PORTS={
22,
53,
80,
443
};
unordered_set<string> baseline_connections;
unordered_set<string> baseline_process_ports;
unordered_map<string,deque<double>> connection_history;
unordered_map<string,deque<double>> beacon_history;
NetworkMonitor(
bool terminal=false,
string config_path="",
bool learn_mode=false,
string csv="",
string json=""
):
learn(learn_mode),
terminal_output(terminal),
export_csv(csv),
export_json(json)
{
(void)config_path;
load_baseline();
}
void load_baseline()
{
ifstream f(BASELINE_FILE);
if(!f.is_open())
return;
string line;
bool connections=false;
bool process_ports=false;
while(getline(f,line))
{
line=trim_string(line);
if(line.find("\"connections\"")!=string::npos)
{
connections=true;
process_ports=false;
continue;
}
if(line.find("\"process_ports\"")!=string::npos)
{
process_ports=true;
connections=false;
continue;
}
if(line.empty())
continue;
if(line.front()=='"')
{
size_t first=line.find('"',1);
if(first==string::npos)
continue;
string value=line.substr(1,first-1);
if(connections&&baseline_connections.size()<MAX_BASELINE_ENTRIES)
baseline_connections.insert(value);
if(process_ports&&baseline_process_ports.size()<MAX_BASELINE_ENTRIES)
baseline_process_ports.insert(value);
}
}
}
void save_baseline()
{
ofstream f(BASELINE_FILE);
if(!f)
return;
f<<"{\n";
f<<"\"connections\": [\n";
size_t count=0;
for(const auto& c:baseline_connections)
{
if(count>=MAX_BASELINE_ENTRIES)
break;
if(count++)
f<<",\n";
f<<"\""<<json_escape(c)<<"\"";
}
f<<"\n],\n";
f<<"\"process_ports\": [\n";
count=0;
for(const auto& p:baseline_process_ports)
{
if(count>=MAX_BASELINE_ENTRIES)
break;
if(count++)
f<<",\n";
f<<"\""<<json_escape(p)<<"\"";
}
f<<"\n]\n";
f<<"}\n";
}
bool rate_limited(const string& key)
{
double current=now_time();
lock_guard<mutex> lock(mtx);
auto it=alert_cache.find(key);
if(it!=alert_cache.end())
{
if(current-it->second<RATE_LIMIT_SECONDS)
return true;
}
alert_cache[key]=current;
return false;
}
void record_alert(
const string& type,
const string& msg,
const string& key,
const string& context="UNKNOWN"
)
{
if(rate_limited(key))
return;
string full=
"["+
context+
"] "+
msg;
{
lock_guard<mutex> lock(mtx);
alerts.emplace_back(
now_time(),
type,
full
);
}
if(terminal_output)
cout<<full<<endl;
}
bool parse_destination(
const string& dest,
string& ip,
int& port
)
{
string value=dest;
if(value.empty())
return false;
if(value.front()=='[')
{
size_t close=value.find(']');
if(close==string::npos)
return false;
ip=value.substr(1,close-1);
if(close+2>=value.size())
return false;
return parse_port(
value.substr(close+2),
port
);
}
size_t pos=value.rfind(':');
if(pos==string::npos)
return false;
ip=value.substr(0,pos);
return parse_port(
value.substr(pos+1),
port
);
}
void process_connection(
const string& line
)
{
istringstream iss(line);
vector<string> cols;
string temp;
while(iss>>temp)
cols.push_back(temp);
if(cols.size()<5)
return;
string ip;
int port;
if(!parse_destination(
cols[4],
ip,
port))
{
return;
}
string proto=cols[0];
string key=
proto+
":"+
ip+
":"+
to_string(port);
double current=now_time();
if(learn)
{
lock_guard<mutex> lock(mtx);
if(baseline_connections.size()<MAX_BASELINE_ENTRIES)
baseline_connections.insert(key);
return;
}
if(is_local_ip(ip)||
is_ephemeral(port))
{
return;
}
if(!baseline_connections.count(key))
{
record_alert(
"first_seen",
"New external connection "+key,
key,
"NET"
);
}
auto& history=connection_history[key];
history.push_back(current);
while(!history.empty()&&
current-history.front()>FREQ_WINDOW)
{
history.pop_front();
}
if((int)history.size()>FREQ_THRESHOLD)
{
record_alert(
"frequency",
"High frequency "+key,
key,
"NET"
);
}
auto& beacon=beacon_history[key];
beacon.push_back(current);
if(beacon.size()>=BEACON_MIN_SAMPLES)
{
vector<double> intervals;
for(size_t i=1;i<beacon.size();i++)
{
intervals.push_back(
beacon[i]-beacon[i-1]
);
}
double avg=
accumulate(
intervals.begin(),
intervals.end(),
0.0
)
/
intervals.size();
double variance=0;
for(double v:intervals)
{
variance+=abs(v-avg);
}
variance/=intervals.size();
if(variance<BEACON_VARIANCE_THRESHOLD)
{
record_alert(
"beaconing",
"Beaconing detected "+key,
key,
"NET"
);
}
if(beacon.size()>20)
beacon.pop_front();
}
if(!ALLOWED_PORTS.count(port))
{
record_alert(
"port",
"Connection to unusual port "+
to_string(port),
key,
"NET"
);
}
}
};
void process_process(
const string& line,
NetworkMonitor& nm
)
{
size_t pid_pos=line.find("pid=");
if(pid_pos==string::npos)
return;
size_t comma=line.find(",",pid_pos);
if(comma==string::npos)
return;
int pid=0;
try
{
pid=stoi(
line.substr(
pid_pos+4,
comma-(pid_pos+4)
)
);
}
catch(...)
{
return;
}
string pname;
{
lock_guard<mutex> lock(nm.mtx);
auto it=nm.proc_cache.find(pid);
if(it!=nm.proc_cache.end())
pname=it->second;
}
if(pname.empty())
{
pname=get_process_name(pid);
lock_guard<mutex> lock(nm.mtx);
if(nm.proc_cache.size()<MAX_BASELINE_ENTRIES)
nm.proc_cache[pid]=pname;
}
istringstream iss(line);
vector<string> cols;
string temp;
while(iss>>temp)
cols.push_back(temp);
if(cols.size()<5)
return;
string ip;
int port;
if(!nm.parse_destination(
cols[4],
ip,
port))
{
return;
}
if(is_ephemeral(port))
return;
string key=
pname+
":"+
to_string(port);
if(nm.learn)
{
lock_guard<mutex> lock(nm.mtx);
if(nm.baseline_process_ports.size()<MAX_BASELINE_ENTRIES)
nm.baseline_process_ports.insert(key);
return;
}
if(SUSPICIOUS_PORTS.count(port))
{
string cmd=get_process_cmd(pid);
string exe=get_process_exe(pid);
nm.record_alert(
"suspicious_port",
"Process ["+
pname+
"] PID "+
to_string(pid)+
" using suspicious port "+
to_string(port)+
"\n CMD: "+
cmd+
"\n EXE: "+
exe,
key,
"PROCESS"
);
}
if(!nm.baseline_process_ports.count(key))
{
string cmd=get_process_cmd(pid);
string exe=get_process_exe(pid);
nm.record_alert(
"process_anomaly",
"Process ["+
pname+
"] PID "+
to_string(pid)+
" unusual port "+
to_string(port)+
"\n CMD: "+
cmd+
"\n EXE: "+
exe,
key,
"PROCESS"
);
}
}
void export_results(
NetworkMonitor& nm
)
{
if(!nm.export_csv.empty())
{
ofstream f(nm.export_csv);
if(f)
{
f<<"timestamp,type,message\n";
for(auto& [ts,type,msg]:nm.alerts)
{
f<<ts
<<","
<<type
<<",\""
<<msg
<<"\"\n";
}
}
}
if(!nm.export_json.empty())
{
ofstream f(nm.export_json);
if(f)
{
f<<"[\n";
for(size_t i=0;i<nm.alerts.size();i++)
{
auto& [ts,type,msg]=nm.alerts[i];
f<<"{\n";
f<<"\"ts\":"
<<ts
<<",\n";
f<<"\"type\":\""
<<json_escape(type)
<<"\",\n";
f<<"\"msg\":\""
<<json_escape(msg)
<<"\"\n";
f<<"}";
if(i+1<nm.alerts.size())
f<<",";
f<<"\n";
}
f<<"]\n";
}
}
}
void run_monitor(
NetworkMonitor& nm,
bool continuous,
bool once,
int duration
)
{
auto scan=
[&nm]()
{
vector<string> connections=
run_command(
"ss -tunH"
);
vector<string> processes=
run_command(
"ss -tunpH"
);
vector<thread> workers;
size_t total=
connections.size()+
processes.size();
size_t limit=
min(
static_cast<size_t>(MAX_WORKERS),
total
);
if(limit==0)
return;
mutex queue_mutex;
size_t index=0;
auto worker=
[&]()
{
while(true)
{
size_t current;
{
lock_guard<mutex> lock(
queue_mutex
);
if(index>=total)
break;
current=index++;
}
if(current<connections.size())
{
nm.process_connection(
connections[current]
);
}
else
{
size_t p=
current-
connections.size();
process_process(
processes[p],
nm
);
}
}
};
for(size_t i=0;i<limit;i++)
{
workers.emplace_back(
worker
);
}
for(auto& t:workers)
{
if(t.joinable())
t.join();
}
};
double start=now_time();
if(once)
{
scan();
}
else if(continuous)
{
while(true)
{
scan();
if(duration>0&&
now_time()-start>=duration)
{
break;
}
this_thread::sleep_for(
chrono::seconds(10)
);
}
}
else
{
scan();
}
if(nm.learn)
nm.save_baseline();
export_results(nm);
}
int main(
int argc,
char* argv[]
)
{
bool continuous=false;
bool once=false;
bool learn=false;
bool terminal=false;
int duration=0;
string export_csv;
string export_json;
try
{
for(int i=1;i<argc;i++)
{
string arg=argv[i];
if(arg=="-c"||
arg=="--continuous")
{
continuous=true;
}
else if(arg=="--once")
{
once=true;
}
else if(arg=="--learn")
{
learn=true;
}
else if(arg=="--terminal")
{
terminal=true;
}
else if(arg=="--duration"&&
i+1<argc)
{
duration=stoi(argv[++i]);
}
else if(arg=="--export-csv"&&
i+1<argc)
{
export_csv=argv[++i];
}
else if(arg=="--export-json"&&
i+1<argc)
{
export_json=argv[++i];
}
else
{
cerr
<<"Unknown option: "
<<arg
<<endl;
}
}
NetworkMonitor nm(
terminal,
"",
learn,
export_csv,
export_json
);
run_monitor(
nm,
continuous,
once,
duration
);
}
catch(const exception& e)
{
cerr
<<"Fatal error: "
<<e.what()
<<endl;
return 1;
}
catch(...)
{
cerr
<<"Unknown fatal error."
<<endl;
return 1;
}
return 0;
}
//g++ -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic PortPeep_1.0.cpp -o portpeep

/* FULL README: 
PortPeep
Network Connection Monitoring and Anomaly Detection Utility

PortPeep is a C++17 network monitoring utility designed to inspect active network connections, associate connections with processes, learn normal system behavior, and report potentially unusual network activity.

The tool is designed as a lightweight local monitoring utility using Linux networking information provided by ss, process information from /proc, and system process queries.

PortPeep focuses on visibility and anomaly detection rather than active scanning or exploitation.

Features
Network Connection Monitoring

PortPeep monitors active TCP and UDP connections and analyzes:

External network connections
Previously unseen destinations
Unusual destination ports
High-frequency communication patterns
Possible beacon-like communication intervals
Process Association

When process information is available, PortPeep attempts to identify:

Process name
Process ID
Command line
Executable path

This allows network activity to be associated with the responsible program.

Example:

PROCESS:
Process [example]
PID 1234
using suspicious port 4444

CMD:
example --service

EXE:
/usr/bin/example
Detection Methods
First Seen Connections

PortPeep maintains a baseline of known connections.

If a connection appears that has not previously been observed:

[NET] New external connection tcp:example.com:443

an alert may be generated.

Connection Frequency Detection

PortPeep tracks connection frequency over time.

Default values:

Window:
60 seconds

Threshold:
20 connections

If a connection repeatedly appears beyond the threshold:

[NET] High frequency tcp:x.x.x.x:port

may be reported.

Beaconing Detection

PortPeep analyzes connection timing intervals.

When repeated connections occur at very consistent intervals, it may indicate automated periodic communication.

Default:

Minimum samples:
5

Variance threshold:
2.0

Example:

[NET] Beaconing detected tcp:x.x.x.x:443
Suspicious Port Detection

PortPeep checks for commonly suspicious ports.

Default monitored ports:

4444
5555
6666
1337
9001

Example:

[PROCESS] Process [example]
PID 1234 using suspicious port 4444
Requirements
Operating System

Designed for Linux systems.

Tested with:

Linux Mint
Ubuntu-based distributions
Debian-based distributions
Dependencies

Required:

g++
C++17 compiler
pthread support
iproute2 (ss command)
proc filesystem

Install compiler tools:

Debian/Ubuntu/Mint:

sudo apt install build-essential iproute2
Compilation

Compile using:

g++ -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic PortPeep_1.0.cpp -o portpeep

The resulting binary:

portpeep

can be executed directly.

Command Line Options
Continuous Monitoring

Option:

-c

or:

--continuous

Description:

Runs PortPeep continuously.

The program will:

Perform a network scan
Analyze connections
Analyze processes
Wait 10 seconds
Repeat

Example:

./portpeep --continuous
Single Scan Mode

Option:

--once

Description:

Performs one monitoring pass and exits.

Example:

./portpeep --once

Useful for:

Manual checks
Scripts
Cron jobs
Incident response
Learning Mode

Option:

--learn

Description:

Creates a baseline of normal activity.

During learning:

Connections are recorded
Process/port relationships are recorded
Alerts are not generated

The baseline is saved to:

baseline.json

Example:

./portpeep --learn

Recommended workflow:

Run on a trusted system state:
./portpeep --learn
Review generated:
baseline.json
Run normally:
./portpeep --once
Terminal Output

Option:

--terminal

Description:

Displays alerts immediately in the terminal.

Example:

./portpeep --once --terminal

Without this option, alerts are still internally recorded and can be exported.

Monitoring Duration

Option:

--duration <seconds>

Description:

Limits continuous monitoring time.

Example:

./portpeep --continuous --duration 300

Runs for:

300 seconds

or:

5 minutes
CSV Export

Option:

--export-csv <file>

Description:

Exports detected alerts into CSV format.

Example:

./portpeep --once --export-csv alerts.csv

Output format:

timestamp,type,message

Example:

1730000000,first_seen,"[NET] New external connection tcp:x.x.x.x:443"
JSON Export

Option:

--export-json <file>

Description:

Exports alerts into JSON format.

Example:

./portpeep --once --export-json alerts.json

Output example:

[
{
"ts":1730000000,
"type":"frequency",
"msg":"[NET] High frequency tcp:x.x.x.x:443"
}
]
Common Usage Examples
Quick System Check
./portpeep --once --terminal
Continuous Monitoring
./portpeep --continuous --terminal
Monitor for 10 Minutes
./portpeep --continuous --duration 600 --terminal
Create Baseline
./portpeep --learn
Export Report
./portpeep \
--once \
--terminal \
--export-json report.json \
--export-csv report.csv
Files Created
baseline.json

Stores known activity.

Contains:

connections
process_ports

Example:

{
"connections":
[
"tcp:example.com:443"
],

"process_ports":
[
"firefox:443"
]
}
Permissions

Normal user execution:

./portpeep

may provide limited process information.

For expanded process visibility:

sudo ./portpeep

may be required.

Use elevated privileges only when necessary.

Performance

PortPeep uses:

Worker threads
Connection caching
Process caching
Rate limiting
Limited baseline storage

Default limits:

Maximum baseline entries:
10000

Alert rate limit:
60 seconds
Security Notes

PortPeep is intended as a defensive monitoring tool.

It:

Does not scan remote systems
Does not exploit services
Does not modify network settings
Does not terminate processes
Does not make automatic remediation decisions

It provides visibility and alerts for investigation.

Troubleshooting
"ss command not found"

Install:

sudo apt install iproute2
Missing process information

Try:

sudo ./portpeep --once --terminal
Empty baseline

Run:

./portpeep --learn

during a trusted normal operating period.

Compiler Errors

Ensure C++17 support:

g++ --version

Compile with:

-std=c++17
Exit Codes

Successful execution:

0

Fatal error:

1
Example Monitoring Workflow

Initial trusted setup:

./portpeep --learn

Normal monitoring:

./portpeep --continuous --terminal

Periodic report:

./portpeep \
--once \
--export-json daily_report.json

Review alerts and investigate unexpected activity.
*/
