#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <mutex>
#include <memory>
#include <cstdlib>
std::mutex log_mutex;
void log_message(const std::string& category, const std::string& message, const std::string& logfile = "") {
    std::string log_file = logfile.empty() ? "update_log.txt" : logfile;
    std::lock_guard<std::mutex> guard(log_mutex);
    std::ofstream ofs(log_file, std::ios::app);
    if (!ofs) return;
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    ofs << "[" << buf << "] [" << category << "] " << message << std::endl;
}
// Helper to run system commands and log output
void run_command(const std::string& command, const std::string& category, const std::string& logfile) {
    int ret = std::system(command.c_str());
    if (ret == 0)
        log_message(category, "Executed securely: " + command, logfile);
    else
        log_message("ERROR", "Failed: " + command + " with error code " + std::to_string(ret), logfile);
}
// Gather system info cross-platform using system commands
void gather_system_info(const std::string& logfile) {
    log_message("INFO", "===== SYSTEM INFORMATION =====", logfile);
#if defined(_WIN32)
    log_message("INFO", "System: Windows", logfile);
    run_command("wmic cpu get NumberOfCores,NumberOfLogicalProcessors", "INFO", logfile);
    run_command("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory", "INFO", logfile);
    run_command("wmic logicaldisk get Name,Size,FreeSpace", "INFO", logfile);
    run_command("ipconfig", "INFO", logfile);
#elif defined(__APPLE__)
    log_message("INFO", "System: macOS", logfile);
    run_command("sysctl -n machdep.cpu.brand_string", "INFO", logfile);
    run_command("sysctl hw.physicalcpu hw.logicalcpu", "INFO", logfile);
    run_command("vm_stat", "INFO", logfile);
    run_command("df -h", "INFO", logfile);
    run_command("ifconfig", "INFO", logfile);
#elif defined(__linux__)
    log_message("INFO", "System: Linux", logfile);
    run_command("lscpu", "INFO", logfile);
    run_command("free -h", "INFO", logfile);
    run_command("df -h", "INFO", logfile);
    run_command("ip addr", "INFO", logfile);
#else
    log_message("INFO", "System: Unknown", logfile);
#endif

    log_message("INFO", "===== END SYSTEM INFORMATION =====", logfile);
}
class BaseUpdater {
public:
    virtual void update(const std::string& logfile) = 0;
    virtual void update_firmware(const std::string& logfile) = 0;
};
class OSXUpdater : public BaseUpdater {
public:
    void update(const std::string& logfile) override {
        log_message("INFO", "Starting macOS update...", logfile);
        run_command("softwareupdate --list", "INFO", logfile);
        run_command("sudo softwareupdate -ia --verbose", "INFO", logfile);
        log_message("INFO", "macOS update completed.", logfile);
    }
    void update_firmware(const std::string& logfile) override {
        log_message("INFO", "Starting macOS firmware update...", logfile);
        run_command("softwareupdate --list", "INFO", logfile);
        run_command("sudo softwareupdate --install-rosetta --agree-to-license", "INFO", logfile);
        log_message("INFO", "macOS firmware update completed.", logfile);
    }
};
class WindowsUpdater : public BaseUpdater {
public:
    void update(const std::string& logfile) override {
        log_message("INFO", "Starting Windows update...", logfile);
        run_command("powershell -Command \"Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate; Install-WindowsUpdate -AcceptAll -AutoReboot\"", "INFO", logfile);
        log_message("INFO", "Windows update completed.", logfile);
    }
    void update_firmware(const std::string& logfile) override {
        log_message("INFO", "Starting Windows firmware update...", logfile);
        run_command("powershell -Command \"Install-Module -Name FirmwareUpdate -Force; Get-FirmwareUpdate; Update-Firmware -All -Confirm:$false\"", "INFO", logfile);
        log_message("INFO", "Windows firmware update completed.", logfile);
    }
};
class LinuxUpdater : public BaseUpdater {
public:
    void update(const std::string& logfile) override {
        log_message("INFO", "Starting Linux update...", logfile);
        if (std::system("which apt > /dev/null 2>&1") == 0) {
            run_command("sudo apt update && sudo apt upgrade -y", "INFO", logfile);
        } else if (std::system("which dnf > /dev/null 2>&1") == 0) {
            run_command("sudo dnf check-update && sudo dnf upgrade -y", "INFO", logfile);
        } else if (std::system("which zypper > /dev/null 2>&1") == 0) {
            run_command("sudo zypper refresh && sudo zypper update -y", "INFO", logfile);
        } else {
            log_message("ERROR", "No supported package manager found.", logfile);
        }
        log_message("INFO", "Linux update completed.", logfile);
    }
    void update_firmware(const std::string& logfile) override {
        log_message("INFO", "Starting Linux firmware update...", logfile);
        if (std::system("which fwupdmgr > /dev/null 2>&1") == 0) {
            run_command("sudo fwupdmgr get-updates && sudo fwupdmgr update", "INFO", logfile);
        } else {
            log_message("ERROR", "fwupdmgr not found for firmware update.", logfile);
        }
        log_message("INFO", "Linux firmware update completed.", logfile);
    }
};
class UpdaterManager {
private:
    std::unique_ptr<BaseUpdater> updater;
public:
    std::string detect_os() {
#if defined(_WIN32)
        updater = std::make_unique<WindowsUpdater>();
        return "windows";
#elif defined(__APPLE__)
        updater = std::make_unique<OSXUpdater>();
        return "macos";
#elif defined(__linux__)
        updater = std::make_unique<LinuxUpdater>();
        return "linux";
#else
        throw std::runtime_error("Unsupported OS");
#endif
    }
    void run(const std::string& logfile) {
        if (updater) {
            updater->update(logfile);
            updater->update_firmware(logfile);
        } else {
            throw std::runtime_error("No updater available");
        }
    }
};
int main() {
    std::string log_filename = "update_log.txt";
    try {
        gather_system_info(log_filename);
        UpdaterManager manager;
        std::string os_name = manager.detect_os();
        log_message("INFO", "Detected OS: " + os_name, log_filename);
        manager.run(log_filename);
        log_message("INFO", "All updates and firmware checks completed.", log_filename);
        std::cout << "Update process completed. Log file created: " << log_filename << std::endl;
    } catch (const std::exception& e) {
        log_message("FATAL", e.what(), log_filename);
        return 1;
    }
    return 0;
}
