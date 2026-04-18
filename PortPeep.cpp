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
#include <unistd.h>
using namespace std;
// Constants
const int RATE_LIMIT_SECONDS = 60;
const int MAX_WORKERS = max(2u, thread::hardware_concurrency() * 2);
const string BASELINE_FILE = "baseline.json";
const size_t MAX_BASELINE_ENTRIES = 10000;
const int FREQ_WINDOW = 60;
const int FREQ_THRESHOLD = 20;
const int BEACON_MIN_SAMPLES = 5;
const double BEACON_VARIANCE_THRESHOLD = 2.0;
unordered_set<int> SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 9001};
// ---------------- HELPERS ----------------
bool is_ephemeral(int port) {
    return port >= 32768 && port <= 60999;
}
bool is_local_ip(const string& ip) {
    return ip == "127.0.0.1" || ip == "::1" || ip.find("127.") == 0;
}
double now_time() {
    return chrono::duration<double>(chrono::system_clock::now().time_since_epoch()).count();
}
vector<string> run_command(const string& cmd) {
    vector<string> lines;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return lines;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        lines.emplace_back(buffer);
    }
    pclose(pipe);
    return lines;
}
string get_process_name(int pid) {
    auto out = run_command("ps -p " + to_string(pid) + " -o comm= 2>/dev/null");
    return out.empty() ? "unknown" : out[0];
}
string get_process_cmd(int pid) {
    auto out = run_command("ps -p " + to_string(pid) + " -o args= 2>/dev/null");
    return out.empty() ? "unknown" : out[0];
}
string get_process_exe(int pid) {
    string path = "/proc/" + to_string(pid) + "/exe";
    char buf[4096];
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf)-1);
    if (len != -1) {
        buf[len] = '\0';
        return string(buf);
    }
    return "unknown";
}
// ---------------- CLASS ----------------
class NetworkMonitor {
public:
    bool learn;
    bool terminal_output;
    string export_csv;
    string export_json;
    vector<tuple<double, string, string>> alerts;
    unordered_map<string, double> alert_cache;
    unordered_map<int, string> proc_cache;
    mutex mtx;
    unordered_set<int> ALLOWED_PORTS = {22, 53, 80, 443};
    unordered_set<string> baseline_connections;
    unordered_set<string> baseline_process_ports;
    unordered_map<string, deque<double>> connection_history;
    unordered_map<string, deque<double>> beacon_history;
    NetworkMonitor(bool terminal=false,
                   string config_path="",
                   bool learn_mode=false,
                   string csv="",
                   string json="")
        : terminal_output(terminal),
          learn(learn_mode),
          export_csv(csv),
          export_json(json)
    {
        load_baseline();
    }
    void load_baseline() {
        ifstream f(BASELINE_FILE);
        if (!f.is_open()) return;
        string line;
        while (getline(f, line)) {}
    }
    void save_baseline() {
        ofstream f(BASELINE_FILE);
        f << "{\n";

        f << "\"connections\": [\n";
        int count = 0;
        for (const auto& c : baseline_connections) {
            if (count++ >= MAX_BASELINE_ENTRIES) break;
            f << "\"" << c << "\",\n";
        }
        f << "],\n";

        f << "\"process_ports\": [\n";
        count = 0;
        for (const auto& p : baseline_process_ports) {
            if (count++ >= MAX_BASELINE_ENTRIES) break;
            f << "\"" << p << "\",\n";
        }
        f << "]\n}\n";
    }
    bool rate_limited(const string& key) {
        double now = now_time();
        lock_guard<mutex> lock(mtx);
        if (alert_cache.count(key)) {
            if (now - alert_cache[key] < RATE_LIMIT_SECONDS)
                return true;
        }
        alert_cache[key] = now;
        return false;
    }
    void record_alert(const string& type,
                      const string& msg,
                      const string& key,
                      const string& context = "UNKNOWN") {

        if (rate_limited(key)) return;
        string full = "[" + context + "] " + msg;
        {
            lock_guard<mutex> lock(mtx);
            alerts.emplace_back(now_time(), type, full);
        }
        cout << full << endl;
    }
    void process_connection(const string& line) {
        istringstream iss(line);
        vector<string> cols;
        string temp;
        while (iss >> temp) cols.push_back(temp);
        if (cols.size() < 5) return;
        string proto = cols[0];
        string dest = cols[4];
        auto pos = dest.rfind(':');
        if (pos == string::npos) return;
        string ip = dest.substr(0, pos);
        string port_str = dest.substr(pos + 1);
        if (!all_of(port_str.begin(), port_str.end(), ::isdigit)) return;
        int port = stoi(port_str);
        string key = proto + ":" + ip + ":" + to_string(port);
        double now = now_time();
        if (is_local_ip(ip) || is_ephemeral(port)) return;
        if (learn) {
            lock_guard<mutex> lock(mtx);
            if (baseline_connections.size() < MAX_BASELINE_ENTRIES)
                baseline_connections.insert(key);
            return;
        }
        if (!baseline_connections.count(key)) {
            record_alert("first_seen",
                         "New external connection " + key,
                         key,
                         "NET");
        }
        auto& hist = connection_history[key];
        hist.push_back(now);
        while (!hist.empty() && now - hist.front() > FREQ_WINDOW)
            hist.pop_front();
        if ((int)hist.size() > FREQ_THRESHOLD) {
            record_alert("frequency",
                         "High frequency " + key,
                         key,
                         "NET");
        }
    }
};
// ---------------- PROCESS ----------------
void process_process(const string& line, NetworkMonitor& nm) {
    if (line.find("pid=") == string::npos) return;
    size_t pid_pos = line.find("pid=");
    size_t comma = line.find(",", pid_pos);
    int pid = stoi(line.substr(pid_pos + 4, comma - (pid_pos + 4)));
    string pname;
    {
        lock_guard<mutex> lock(nm.mtx);
        if (nm.proc_cache.count(pid)) {
            pname = nm.proc_cache[pid];
        } else {
            pname = get_process_name(pid);
            nm.proc_cache[pid] = pname;
        }
    }
    istringstream iss(line);
    vector<string> cols;
    string temp;
    while (iss >> temp) cols.push_back(temp);
    if (cols.size() < 5) return;
    string dest = cols[4];
    auto pos = dest.rfind(':');
    if (pos == string::npos) return;
    string port_str = dest.substr(pos + 1);
    if (!all_of(port_str.begin(), port_str.end(), ::isdigit)) return;
    int port = stoi(port_str);
    if (is_ephemeral(port)) return;
    string key = pname + ":" + to_string(port);
    if (nm.learn) {
        lock_guard<mutex> lock(nm.mtx);
        if (nm.baseline_process_ports.size() < MAX_BASELINE_ENTRIES)
            nm.baseline_process_ports.insert(key);
        return;
    }
    string cmd = get_process_cmd(pid);
    string exe = get_process_exe(pid);
    if (SUSPICIOUS_PORTS.count(port)) {
        nm.record_alert("suspicious_port",
            "Process [" + pname + "] (PID " + to_string(pid) +
            ") using suspicious port " + to_string(port) +
            "\n  CMD: " + cmd +
            "\n  EXE: " + exe,
            key,
            "PROCESS");
    }
    if (!nm.baseline_process_ports.count(key)) {
        nm.record_alert("process_anomaly",
            "Process [" + pname + "] (PID " + to_string(pid) +
            ") unusual port " + to_string(port) +
            "\n  CMD: " + cmd +
            "\n  EXE: " + exe,
            key,
            "PROCESS");
    }
}
// ---------------- RUN + MAIN (unchanged) ----------------
void run_monitor(NetworkMonitor& nm,
                 bool continuous,
                 bool once,
                 int duration) {
    auto once_scan = [&nm]() {
        vector<string> conns = run_command("ss -tunH");
        vector<string> procs = run_command("ss -tunpH");
        if (conns.size() < 100) {
            for (auto& l : conns)
                nm.process_connection(l);
            for (auto& l : procs)
                process_process(l, nm);
        } else {
            vector<thread> workers;
            for (auto& l : conns) {
                workers.emplace_back([&nm, l]() {
                    nm.process_connection(l);
                });
            }
            for (auto& l : procs) {
                workers.emplace_back([&nm, l]() {
                    process_process(l, nm);
                });
            }
            for (auto& t : workers)
                t.join();
        }
    };
    double start_time = now_time();
    if (once) {
        once_scan();
        return;
    }
    if (continuous) {
        while (true) {
            once_scan();
            if (duration > 0 && (now_time() - start_time) >= duration)
                break;
            this_thread::sleep_for(chrono::seconds(10));
        }
    } else {
        once_scan();
    }
    if (nm.learn) nm.save_baseline();
    if (!nm.export_csv.empty()) {
        ofstream f(nm.export_csv);
        for (auto& [ts, typ, msg] : nm.alerts)
            f << ts << "," << typ << "," << msg << "\n";
    }
    if (!nm.export_json.empty()) {
        ofstream f(nm.export_json);
        f << "[\n";
        for (auto& [ts, typ, msg] : nm.alerts) {
            f << "{ \"ts\": " << ts
              << ", \"type\": \"" << typ
              << "\", \"msg\": \"" << msg << "\" },\n";
        }
        f << "]\n";
    }
}
// ---------------- MAIN ----------------
int main(int argc, char* argv[]) {
    bool continuous = false;
    bool once = false;
    bool learn = false;
    bool terminal = false;
    int duration = 0;
    string export_csv;
    string export_json;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-c" || arg == "--continuous")
            continuous = true;
        else if (arg == "--once")
            once = true;
        else if (arg == "--learn")
            learn = true;
        else if (arg == "--terminal")
            terminal = true;
        else if (arg == "--duration" && i + 1 < argc)
            duration = stoi(argv[++i]);
        else if (arg == "--export-csv" && i + 1 < argc)
            export_csv = argv[++i];
        else if (arg == "--export-json" && i + 1 < argc)
            export_json = argv[++i];
    }
    NetworkMonitor nm(terminal, "", learn, export_csv, export_json);
    try {
        run_monitor(nm, continuous, once, duration);
    } catch (...) {
        return 0;
    }
    return 0;
}
