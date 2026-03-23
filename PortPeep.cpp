#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <sys/statvfs.h>
#include <future>  // For async operations
using json = nlohmann::json;
// ================= CONFIG =================
const int RATE_LIMIT_SECONDS = 60;
const std::string BASELINE_FILE = "baseline.json";
const std::string LOG_FILE = "/var/log/network_monitor.log";
const size_t MAX_LOG_SIZE = 5 * 1024 * 1024;
const double DISK_USAGE_THRESHOLD = 0.95;  // 95% disk usage
// ================= THREAD POOL =================
class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex mtx;
    std::condition_variable cv;
    bool stop = false;
public:
    ThreadPool(size_t n) {
        for (size_t i = 0; i < n; ++i) {
            workers.emplace_back([this]() {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock lock(mtx);
                        cv.wait(lock, [this]() { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    void enqueue(std::function<void()> f) {
        {
            std::lock_guard lock(mtx);
            tasks.push(f);
        }
        cv.notify_one();
    }
    void shutdown() {
        {
            std::lock_guard lock(mtx);
            stop = true;
        }
        cv.notify_all();
        for (auto &t : workers) t.join();
    }
};
// ================= LOGGING =================
std::mutex log_mtx;
void rotate_logs() {
    std::ifstream f(LOG_FILE, std::ios::binary | std::ios::ate);
    if (!f) return;
    if (f.tellg() < MAX_LOG_SIZE) return;
    f.close();
    std::rename(LOG_FILE.c_str(), (LOG_FILE + ".1").c_str());
}
void log_msg(const std::string &msg) {
    std::lock_guard lock(log_mtx);
    rotate_logs();
    std::ofstream f(LOG_FILE, std::ios::app);
    f << msg << std::endl;
}
// ================= UTIL =================
std::vector<std::string> split(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> v;
    std::string x;
    while (iss >> x) v.push_back(x);
    return v;
}
std::vector<std::string> run_ss(const std::string &args) {
    std::vector<std::string> lines;
    std::string cmd = "ss " + args;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) return lines;
    char buffer[4096];
    bool skip = true;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        if (skip) { skip = false; continue; }
        std::string line(buffer);
        if (!line.empty() && line.back() == '\n') line.pop_back();
        lines.emplace_back(line);
    }
    pclose(pipe);
    return lines;
}
// ================= IP RANGE =================
class CIDR {
    in_addr net{};
    in_addr mask{};
public:
    CIDR(const std::string &cidr) {
        auto pos = cidr.find('/');
        std::string ip = cidr.substr(0, pos);
        int bits = std::stoi(cidr.substr(pos + 1));
        inet_pton(AF_INET, ip.c_str(), &net.s_addr);
        uint32_t m = bits == 0 ? 0 : htonl(~((1 << (32 - bits)) - 1));
        mask.s_addr = m;
    }
    bool contains(const std::string &ip) const {
        in_addr addr{};
        if (inet_pton(AF_INET, ip.c_str(), &addr.s_addr) != 1)
            return false;
        return (addr.s_addr & mask.s_addr) == (net.s_addr & mask.s_addr);
    }
};
// ================= PROCESS NAME =================
std::string get_process_name(int pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    if (!f) return "unknown";
    std::string name;
    std::getline(f, name);
    return name;
}
// ================= ASYNCHRONOUS DISK SPACE CHECK =================
std::future<bool> check_disk_space_async(const std::string& path = "/") {
    return std::async(std::launch::async, [path]() {
        struct statvfs stat;
        if (statvfs(path.c_str(), &stat) != 0) {
            std::cerr << "Failed to get disk space information for " << path << "\n";
            return false;
        }
        unsigned long total_space = stat.f_blocks * stat.f_frsize;
        unsigned long free_space = stat.f_bfree * stat.f_frsize;
        double used_percentage = 1.0 - (static_cast<double>(free_space) / static_cast<double>(total_space));
        if (used_percentage > DISK_USAGE_THRESHOLD) {
            std::cerr << "Disk usage is above 95%. Terminating program.\n";
            return false;  // Disk space is over the threshold
        }
        return true;  // Disk space is within safe limits
    });
}
// ================= MAIN CLASS =================
class NetworkMonitor {
public:
    bool learn = false;
    bool terminal = false;
    std::set<int> allowed_ports{22,53,443,8080};
    std::vector<CIDR> allowed_ranges;
    std::map<std::string, std::vector<int>> allowed_processes;
    std::set<std::string> baseline_conn;
    std::set<std::string> baseline_proc;
    std::vector<std::string> alerts;
    std::map<std::string, time_t> cache;
    std::mutex mtx;
    NetworkMonitor() {
        allowed_ranges.emplace_back("127.0.0.0/8");
        allowed_ranges.emplace_back("192.168.1.0/24");
        load_baseline();
    }
    void load_config(const std::string &path) {
        std::ifstream f(path);
        if (!f) return;
        json j; f >> j;
        if (j.contains("ports") && j["ports"].is_array()) {
            for (auto &p : j["ports"])
                if (p.is_number_integer())
                    allowed_ports.insert(p.get<int>());
        }
        if (j.contains("ip_ranges") && j["ip_ranges"].is_array()) {
            for (auto &r : j["ip_ranges"])
                if (r.is_string())
                    allowed_ranges.emplace_back(r.get<std::string>());
        }
        if (j.contains("processes") && j["processes"].is_object()) {
            for (auto &[k, v] : j["processes"].items()) {
                if (v.is_array()) {
                    std::vector<int> ports;
                    for (auto &p : v)
                        if (p.is_number_integer())
                            ports.push_back(p.get<int>());
                    allowed_processes[k] = ports;
                }
            }
        }
    }
    void load_baseline() {
        std::ifstream f(BASELINE_FILE);
        if (!f) return;
        json j; f >> j;
        if (j.contains("connections") && j["connections"].is_array()) {
            for (auto &x : j["connections"])
                if (x.is_string())
                    baseline_conn.insert(x.get<std::string>());
        }
        if (j.contains("process_ports") && j["process_ports"].is_array()) {
            for (auto &x : j["process_ports"])
                if (x.is_string())
                    baseline_proc.insert(x.get<std::string>());
        }
    }
    void save_baseline() {
        json j;
        j["connections"] = baseline_conn;
        j["process_ports"] = baseline_proc;
        std::ofstream f(BASELINE_FILE);
        f << j.dump(2);
    }
    bool allowed_ip(const std::string &ip) {
        for (auto &r : allowed_ranges)
            if (r.contains(ip)) return true;
        return false;
    }
    bool rate_limited(const std::string &k) {
        time_t now = time(nullptr);
        if (cache.count(k) && now - cache[k] < RATE_LIMIT_SECONDS)
            return true;
        cache[k] = now;
        return false;
    }
    void process_conn(const std::string &line) {
        auto c = split(line);
        if (c.size() < 5) return;
        auto pos = c[4].rfind(':');
        if (pos == std::string::npos) return;
        std::string ip = c[4].substr(0,pos);
        std::string port_str = c[4].substr(pos+1);
        if (!std::all_of(port_str.begin(), port_str.end(), ::isdigit)) return;
        int port = std::stoi(port_str);
        std::string key = c[0] + ":" + ip + ":" + std::to_string(port);
        if (learn) {
            baseline_conn.insert(key);
            return;
        }
        if (baseline_conn.count(key)) return;
        if (!allowed_ports.count(port) && !allowed_ip(ip)) {
            if (rate_limited(key)) return;
            std::string msg = "Unusual outbound connection " + key;
            std::lock_guard lock(mtx);
            alerts.push_back(msg);
            log_msg(msg);
            if (terminal) std::cout << msg << "\n";
        }
    }
    void process_proc(const std::string &line) {
        if (line.find("pid=") == std::string::npos) return;
        auto c = split(line);
        if (c.size() < 5) return;
        size_t start = line.find("pid=") + 4;
        size_t end = line.find(',', start);
        std::string pid_str = (end == std::string::npos)
            ? line.substr(start)
            : line.substr(start, end - start);
        int pid = 0;
        try { pid = std::stoi(pid_str); }
        catch (...) { return; }
        std::string pname = get_process_name(pid);
        auto pos = c[4].rfind(':');
        if (pos == std::string::npos) return;
        std::string port_str = c[4].substr(pos+1);
        if (!std::all_of(port_str.begin(), port_str.end(), ::isdigit)) return;
        int port = std::stoi(port_str);
        std::string key = pname + ":" + std::to_string(port);
        if (learn) {
            baseline_proc.insert(key);
            return;
        }
        if (baseline_proc.count(key)) return;
        auto allowed = allowed_processes[pname];
        if (std::find(allowed.begin(), allowed.end(), port) == allowed.end()
            && !allowed_ports.count(port)) {
            if (rate_limited(key)) return;
            std::string msg = "Process " + pname +
                " (PID " + std::to_string(pid) + ") using port " + std::to_string(port);
            std::lock_guard lock(mtx);
            alerts.push_back(msg);
            log_msg(msg);
            if (terminal) std::cout << msg << "\n";
        }
    }
    void run(bool continuous, bool once, int duration) {
        if (geteuid() != 0) {
            std::cerr << "Must run as root\n";
            return;
        }
        auto disk_space_check = check_disk_space_async();  // Start the async disk check
        if (disk_space_check.get() == false) {  // Wait for async result and terminate if disk space is too high
            std::cerr << "Disk space usage is over the threshold. Terminating program.\n";
            return;  // Exit if disk usage exceeds threshold
        }
        ThreadPool pool(std::thread::hardware_concurrency()*2);
        auto scan = [this, &pool]() {
            for (auto &l : run_ss("-tun"))
                pool.enqueue([this, l]{ process_conn(l); });
            for (auto &l : run_ss("-tunp"))
                pool.enqueue([this, l]{ process_proc(l); });
        };
        auto start = std::chrono::steady_clock::now();
        if (once) {
            scan();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            print();
            if (learn) save_baseline();
            pool.shutdown();
            return;
        }
        do {
            scan();
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (duration > 0) {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now-start).count() >= duration)
                    break;
            }
        } while (continuous);
        if (learn) save_baseline();
        pool.shutdown();
    }
    void print() {
        if (alerts.empty()) {
            std::cout << "No alerts\n";
            return;
        }
        for (size_t i=0;i<alerts.size();++i)
            std::cout << i+1 << ". " << alerts[i] << "\n";
    }
};
void print_help() {
    std::cout << "Usage: portpeep [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help                Show this help message\n";
    std::cout << "  --continuous              Run continuously (poll every 10 seconds)\n";
    std::cout << "  --once                    Run one-time scan and display results immediately\n";
    std::cout << "  --learn                   Learn baseline instead of alerting\n";
    std::cout << "  --terminal                Also log alerts to the terminal\n";
    std::cout << "  --config <path>           Path to JSON config file\n";
    std::cout << "  --duration <seconds>      Run for N seconds before exiting (continuous only)\n";
}
int main(int argc, char* argv[]) {
    if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        print_help();
        return 0;
    }
    NetworkMonitor nm;
    bool continuous=false, once=false;
    int duration=0;
    for (int i=1;i<argc;++i) {
        std::string a = argv[i];
        if (a=="--continuous") continuous=true;
        else if (a=="--once") once=true;
        else if (a=="--learn") nm.learn=true;
        else if (a=="--terminal") nm.terminal=true;
        else if (a=="--config" && i+1<argc) nm.load_config(argv[++i]);
        else if (a=="--duration" && i+1<argc) duration=std::stoi(argv[++i]);
    }
    nm.run(continuous, once, duration);
}
