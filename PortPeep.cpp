#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <set>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <functional>          // FIX
#include <condition_variable>  // FIX
using namespace std;
namespace fs = std::filesystem;
constexpr uint64_t DISK_SPACE_THRESHOLD =
    1ULL * 1024 * 1024 * 1024; // 1GB
constexpr int RATE_LIMIT_SECONDS = 60;
constexpr int SCAN_INTERVAL_SECONDS = 10;
static const set<int> ALLOWED_PORTS = {22, 53, 80, 443};
atomic<bool> running(true);
mutex log_mutex;
mutex rate_mutex;
unordered_map<string, time_t> alert_cache;
uint64_t free_disk_bytes() {
    auto s = fs::space("/");
    return s.available;
}
bool rate_limited(const string& key) {
    lock_guard<mutex> lock(rate_mutex);
    time_t now = time(nullptr);
    if (alert_cache.count(key) &&
        now - alert_cache[key] < RATE_LIMIT_SECONDS)
        return true;
    alert_cache[key] = now;
    return false;
}
string exec_cmd(const string& cmd) {
    string data;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return data;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe))
        data += buf;
    pclose(pipe);
    return data;
}
string get_process_name(pid_t pid) {
    ifstream f("/proc/" + to_string(pid) + "/comm");
    string name;
    getline(f, name);
    return name.empty() ? "unknown" : name;
}
bool is_loopback(const string& ip) {
    return ip == "127.0.0.1" || ip == "::1";
}
void log_msg(const string& lvl, const string& msg, bool terminal) {
    lock_guard<mutex> lock(log_mutex);
    ofstream log("/var/log/network_monitor.log", ios::app);
    string line = lvl + ": " + msg;
    log << line << "\n";
    if (terminal)
        cout << line << endl;
}
class ThreadPool {
public:
    explicit ThreadPool(size_t n) {
        for (size_t i = 0; i < n; ++i) {
            workers.emplace_back([this] {
                while (running) {
                    function<void()> job;
                    {
                        unique_lock<mutex> lock(m);
                        cv.wait(lock, [&] {
                            return !jobs.empty() || !running;
                        });
                        if (!running) return;
                        job = move(jobs.back());
                        jobs.pop_back();
                    }
                    job();
                }
            });
        }
    }
    void submit(function<void()> fn) {
        {
            lock_guard<mutex> lock(m);
            jobs.push_back(move(fn));
        }
        cv.notify_one();
    }
    ~ThreadPool() {
        running = false;
        cv.notify_all();
        for (auto& t : workers)
            if (t.joinable()) t.join();
    }
private:
    vector<thread> workers;
    vector<function<void()>> jobs;
    mutex m;
    condition_variable cv;
};
void process_connection(const string& line, bool terminal) {
    istringstream iss(line);
    vector<string> cols;
    string c;
    while (iss >> c) cols.push_back(c);
    if (cols.size() < 5) return;
    string proto = cols[0];
    string dest = cols[4];
    auto pos = dest.rfind(':');
    if (pos == string::npos) return;
    string ip = dest.substr(0, pos);
    int port = stoi(dest.substr(pos + 1));
    if (is_loopback(ip)) return;
    string key = "conn:" + ip + ":" + to_string(port) + ":" + proto;
    if (!ALLOWED_PORTS.count(port)) {
        if (rate_limited(key)) return;
        log_msg("WARN", "Unusual outbound connection " + ip + ":" +
                to_string(port) + " (" + proto + ")", terminal);
    }
}
void process_process(const string& line, bool terminal) {
    if (line.find("pid=") == string::npos) return;
    auto pid_pos = line.find("pid=");
    pid_t pid = stoi(line.substr(pid_pos + 4));
    auto pos = line.rfind(':');
    if (pos == string::npos) return;
    int port = stoi(line.substr(pos + 1));
    if (ALLOWED_PORTS.count(port)) return;
    string key = "proc:" + to_string(pid) + ":" + to_string(port);
    if (rate_limited(key)) return;
    string pname = get_process_name(pid);
    log_msg("WARN", "Process " + pname + " (PID " +
            to_string(pid) + ") using port " +
            to_string(port), terminal);
}
void run_monitor(bool continuous, bool terminal) {
    if (geteuid() != 0) {
        cerr << "Must be run as root\n";
        return;
    }
    size_t threads = max<size_t>(2, thread::hardware_concurrency() * 2);
    ThreadPool pool(threads);
    auto run_once = [&] {
        if (free_disk_bytes() < DISK_SPACE_THRESHOLD) {
            log_msg("ERROR", "Disk space low — stopping", terminal);
            running = false;
            return;
        }
        string conns = exec_cmd("ss -tun");
        string procs = exec_cmd("ss -tunp");
        istringstream c(conns), p(procs);
        string line;
        getline(c, line);
        while (getline(c, line))
            pool.submit([=]{ process_connection(line, terminal); });
        getline(p, line);
        while (getline(p, line))
            pool.submit([=]{ process_process(line, terminal); });
    };
    log_msg("INFO", "Network monitor started", terminal);
    if (continuous) {
        while (running) {
            run_once();
            this_thread::sleep_for(chrono::seconds(SCAN_INTERVAL_SECONDS));
        }
    } else {
        run_once();
        log_msg("INFO", "One-time scan completed", terminal);
    }
}
void sigint(int) {
    running = false;
    cout << "\nStopped by user\n";
}
int main(int argc, char** argv) {
    bool continuous = false;
    bool one_time = false;
    bool terminal = false;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--continuous" || a == "-c") continuous = true;
        else if (a == "--one-time" || a == "-o") one_time = true;
        else if (a == "--terminal") terminal = true;
    }
    if (!continuous && !one_time) {
        cout << "Usage:\n"
             << "  --continuous | -c   Run continuously\n"
             << "  --one-time   | -o   Run once\n"
             << "  --terminal          Output to terminal\n";
        return 0;
    }
    signal(SIGINT, sigint);
    if (continuous)
        run_monitor(true, terminal);
    else
        run_monitor(false, terminal);
    return 0;
}
