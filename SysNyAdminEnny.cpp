#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <map>
#include <sstream>
#include <unistd.h> // for gethostname
#include <stdexcept> // For exception handling
#include <cstdio> // For popen()
#include <array>
using namespace std;
mutex logMutex;
ofstream logFile;
class OSUpdater {
public:
    virtual void updateCache() = 0;
    virtual void checkForUpdates() = 0;
    virtual void downloadUpdates() = 0;
    virtual void installUpdates() = 0;
    virtual void cleanUp() = 0;
    virtual ~OSUpdater() = default;
};
void logMessage(const string& message) {
    lock_guard<mutex> lock(logMutex);

    if (!logFile.is_open()) {
        cerr << "Log file is not open. Message skipped.\n";
        return;
    }
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    string dt(buf);
    logFile << "[" << dt << "] " << message << endl;
    cout << message << endl;
}

class OSXUpdater : public OSUpdater {
private:
    void log(const string& msg) { logMessage("[MacOS] " + msg); }
public:
    void updateCache() override {
        try {
            log("Updating cache...");
            if (system("brew update > /dev/null 2>&1") != 0) {
                throw runtime_error("Failed to update brew.");
            }
        } catch (const exception& e) {
            log("Error in updateCache: " + string(e.what()));
        }
    }

    void checkForUpdates() override {
        try {
            log("Checking for updates...");
            if (system("softwareupdate -l > /dev/null 2>&1") != 0) {
                throw runtime_error("Failed to check for software updates.");
            }
        } catch (const exception& e) {
            log("Error in checkForUpdates: " + string(e.what()));
        }
    }

    void downloadUpdates() override {
        try {
            log("Downloading updates...");
            if (system("softwareupdate -d -a > /dev/null 2>&1") != 0) {
                throw runtime_error("Failed to download updates.");
            }
        } catch (const exception& e) {
            log("Error in downloadUpdates: " + string(e.what()));
        }
    }

    void installUpdates() override {
        try {
            log("Installing updates...");
            if (system("softwareupdate -i -a > /dev/null 2>&1") != 0) {
                throw runtime_error("Failed to install updates.");
            }
        } catch (const exception& e) {
            log("Error in installUpdates: " + string(e.what()));
        }
    }

    void cleanUp() override {
        try {
            log("Cleaning up...");
            if (system("brew cleanup > /dev/null 2>&1") != 0) {
                throw runtime_error("Failed to clean up brew.");
            }
        } catch (const exception& e) {
            log("Error in cleanUp: " + string(e.what()));
        }
    }
};
// WindowsUpdater and LinuxUpdater classes will follow the same pattern as OSXUpdater.
// The second part of the code will include those.
// WindowsUpdater class
class WindowsUpdater : public OSUpdater {
private:
    void log(const string& msg) { logMessage("[Windows] " + msg); }
public:
    void updateCache() override {
        try {
            log("Updating cache...");
            if (system("choco outdated > nul 2>&1") != 0) {
                throw runtime_error("Failed to update chocolatey.");
            }
        } catch (const exception& e) {
            log("Error in updateCache: " + string(e.what()));
        }
    }

    void checkForUpdates() override {
        try {
            log("Checking for updates...");
            if (system("choco outdated > nul 2>&1") != 0) {
                throw runtime_error("Failed to check for chocolatey updates.");
            }
        } catch (const exception& e) {
            log("Error in checkForUpdates: " + string(e.what()));
        }
    }

    void downloadUpdates() override {
        try {
            log("Downloading updates...");
            if (system("choco upgrade all -y --noop > nul 2>&1") != 0) {
                throw runtime_error("Failed to download chocolatey updates.");
            }
        } catch (const exception& e) {
            log("Error in downloadUpdates: " + string(e.what()));
        }
    }

    void installUpdates() override {
        try {
            log("Installing updates...");
            if (system("choco upgrade all -y > nul 2>&1") != 0) {
                throw runtime_error("Failed to install chocolatey updates.");
            }
        } catch (const exception& e) {
            log("Error in installUpdates: " + string(e.what()));
        }
    }
    void cleanUp() override {
        try {
            log("Cleaning up...");
            if (system("choco clean > nul 2>&1") != 0) {
                throw runtime_error("Failed to clean up chocolatey.");
            }
        } catch (const exception& e) {
            log("Error in cleanUp: " + string(e.what()));
        }
    }
};
class LinuxUpdater : public OSUpdater {
private:
    void log(const string& msg) { logMessage("[Linux] " + msg); }

    bool commandExists(const string& cmd) {
        string check = "command -v " + cmd + " > /dev/null 2>&1";
        return system(check.c_str()) == 0;
    }

public:
    void updateCache() override {
        try {
            log("Updating cache...");
            if (commandExists("apt-get")) {
                if (system("sudo apt-get update > /dev/null 2>&1") != 0) throw runtime_error("apt-get update failed.");
            }
            else if (commandExists("dnf")) {
                if (system("sudo dnf check-update > /dev/null 2>&1") != 0) throw runtime_error("dnf check-update failed.");
            }
            else if (commandExists("zypper")) {
                if (system("sudo zypper refresh > /dev/null 2>&1") != 0) throw runtime_error("zypper refresh failed.");
            }
            else if (commandExists("pacman")) {
                if (system("sudo pacman -Sy > /dev/null 2>&1") != 0) throw runtime_error("pacman update failed.");
            }
            else {
                log("No known package manager found.");
            }
        } catch (const exception& e) {
            log("Error in updateCache: " + string(e.what()));
        }
    }

    void checkForUpdates() override {
        try {
            log("Checking for updates...");
            if (commandExists("apt-get")) {
                if (system("apt list --upgradable > /dev/null 2>&1") != 0) throw runtime_error("apt list failed.");
            }
            else if (commandExists("dnf")) {
                if (system("dnf check-update > /dev/null 2>&1") != 0) throw runtime_error("dnf check-update failed.");
            }
            else if (commandExists("zypper")) {
                if (system("zypper lu > /dev/null 2>&1") != 0) throw runtime_error("zypper lu failed.");
            }
            else if (commandExists("pacman")) {
                if (system("pacman -Qu > /dev/null 2>&1") != 0) throw runtime_error("pacman update check failed.");
            }
            else {
                log("No known package manager found.");
            }
        } catch (const exception& e) {
            log("Error in checkForUpdates: " + string(e.what()));
        }
    }
    void downloadUpdates() override {
        try {
            log("Downloading updates...");
            if (commandExists("apt-get")) {
                if (system("sudo apt-get -d upgrade > /dev/null 2>&1") != 0) throw runtime_error("Failed to download updates using apt.");
            }
            else if (commandExists("dnf")) {
                if (system("sudo dnf upgrade --downloadonly > /dev/null 2>&1") != 0) throw runtime_error("Failed to download updates using dnf.");
            }
            else if (commandExists("zypper")) {
                if (system("sudo zypper download > /dev/null 2>&1") != 0) throw runtime_error("Failed to download updates using zypper.");
            }
            else if (commandExists("pacman")) {
                log("Pacman downloads during install.");
            }
            else {
                log("No known package manager found.");
            }
        } catch (const exception& e) {
            log("Error in downloadUpdates: " + string(e.what()));
        }
    }
    void installUpdates() override {
        try {
            log("Installing updates...");
            if (commandExists("apt-get")) {
                if (system("sudo apt-get upgrade -y > /dev/null 2>&1") != 0) throw runtime_error("Failed to install updates using apt.");
            }
            else if (commandExists("dnf")) {
                if (system("sudo dnf upgrade -y > /dev/null 2>&1") != 0) throw runtime_error("Failed to install updates using dnf.");
            }
            else if (commandExists("zypper")) {
                if (system("sudo zypper update -y > /dev/null 2>&1") != 0) throw runtime_error("Failed to install updates using zypper.");
            }
            else if (commandExists("pacman")) {
                if (system("sudo pacman -Su --noconfirm > /dev/null 2>&1") != 0) throw runtime_error("Failed to install updates using pacman.");
            }
            else {
                log("No known package manager found.");
            }
        } catch (const exception& e) {
            log("Error in installUpdates: " + string(e.what()));
        }
    }
    void cleanUp() override {
        try {
            log("Cleaning up...");
            if (commandExists("apt-get")) {
                if (system("sudo apt-get autoremove -y > /dev/null 2>&1") != 0) throw runtime_error("Failed to clean up using apt.");
            }
            else if (commandExists("dnf")) {
                if (system("sudo dnf autoremove -y > /dev/null 2>&1") != 0) throw runtime_error("Failed to clean up using dnf.");
            }
            else if (commandExists("zypper")) {
                if (system("sudo zypper clean > /dev/null 2>&1") != 0) throw runtime_error("Failed to clean up using zypper.");
            }
            else if (commandExists("pacman")) {
                if (system("sudo pacman -Rns $(pacman -Qdtq) --noconfirm > /dev/null 2>&1") != 0) throw runtime_error("Failed to clean up using pacman.");
            }
            else {
                log("No known package manager found.");
            }
        } catch (const exception& e) {
            log("Error in cleanUp: " + string(e.what()));
        }
    }
};
class UpdaterManager {
private:
    unique_ptr<OSUpdater> updater;
    string osType;
    string detectOS() {
        if (system("ver > nul 2>&1") == 0) return "Windows";
        if (system("uname -s > /dev/null 2>&1") == 0) {
            ifstream osRelease("/etc/os-release");
            if (!osRelease.is_open()) {
                cerr << "Failed to open /etc/os-release\n";
                return "Linux";
            }
            string line;
            while (getline(osRelease, line)) {
                if (line.find("NAME=") == 0) {
                    string val = line.substr(5);
                    if (!val.empty() && val.front() == '"')
                        val = val.substr(1, val.size() - 2);
                    return val;
                }
            }
            return "Linux";
        }
        return "MacOS";
    }
public:
    UpdaterManager() {
        osType = detectOS();
        if (osType.find("MacOS") != string::npos) updater = make_unique<OSXUpdater>();
        else if (osType.find("Windows") != string::npos) updater = make_unique<WindowsUpdater>();
        else updater = make_unique<LinuxUpdater>();
    }
    string getOS() { return osType; }
    void performUpdate() {
        updater->updateCache();
        updater->checkForUpdates();
        updater->downloadUpdates();
        updater->installUpdates();
        updater->cleanUp();
    }
};
string gatherSystemInfo() {
    ostringstream ss;
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        ss << "Hostname: " << hostname << "\n";
    } else {
        ss << "Hostname: unavailable\n";
    }
    char* user = getenv("USER");
    if (user) ss << "User: " << user << "\n";
    else ss << "User: unavailable\n";
    time_t now = time(0);
    char* timeStr = ctime(&now);
    if (timeStr) ss << "Current Time: " << timeStr;
    else ss << "Current Time: unavailable\n";
    return ss.str();
}
void showHelp() {
    cout << "Usage:\n";
    cout << "  --r [-f file]     Perform system update (log to file, default system_update.log)\n";
    cout << "  --os [-f file]    Show detected OS (or log to file)\n";
    cout << "  --info [-f file]  Show system info (or log to file)\n";
    cout << "  --help            Show this help message\n";
}
int main(int argc, char* argv[]) {
    UpdaterManager manager;
    if (argc > 1) {
        string arg1 = argv[1];
        if (arg1 == "--r") {
            if (argc > 3 && string(argv[2]) == "-f") {
                logFile.open(argv[3], ios::app);
            } else {
                logFile.open("system_update.log", ios::app);
            }

            if (!logFile.is_open()) {
                cerr << "Failed to open log file.\n";
                return 1;
            }

            try {
                manager.performUpdate();
            } catch (const exception& e) {
                cerr << "Exception caught during update: " << e.what() << endl;
            }
            logFile.close();
            return 0;
        }
        else if (arg1 == "--os") {
            string os = manager.getOS();
            if (argc > 3 && string(argv[2]) == "-f") {
                ofstream out(argv[3]);
                if (!out.is_open()) {
                    cerr << "Failed to open output file.\n";
                    return 1;
                }
                out << "Detected OS: " << os << endl;
            } else {
                cout << "Detected OS: " << os << endl;
            }
            return 0;
        }
        else if (arg1 == "--info") {
            string info = gatherSystemInfo();
            if (argc > 3 && string(argv[2]) == "-f") {
                ofstream out(argv[3]);
                if (!out.is_open()) {
                    cerr << "Failed to open output file.\n";
                    return 1;
                }
                out << info;
            } else {
                cout << info;
            }
            return 0;
        }
        else if (arg1 == "--help") {
            showHelp();
            return 0;
        }
        else {
            cout << "Unknown option: " << arg1 << "\n";
            showHelp();
            return 1;
        }
    }
    cout << "No arguments provided.\n";
    showHelp();
}
