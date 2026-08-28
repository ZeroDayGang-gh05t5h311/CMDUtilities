#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <mutex>
#include <memory>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <filesystem>
#include <cstdio>
#include <array>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace std;

namespace fs = std::filesystem;

mutex log_mutex;

void log_message(const string& category,const string& message,const string& logfile="") {
    string log_file=logfile.empty() ? "update_log.txt" : logfile;
    lock_guard<mutex> guard(log_mutex);
    ofstream ofs(log_file,ios::app);
    if(!ofs) {
        cerr<<"Unable to open log file: "<<log_file<<endl;
        return;
    }
    time_t now=time(nullptr);
    char buf[64]{};
#ifdef _WIN32
    tm tm_buf{};
    localtime_s(&tm_buf,&now);
#else
    tm tm_buf{};
    localtime_r(&now,&tm_buf);
#endif
    strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&tm_buf);
    ofs<<"["<<buf<<"] ["<<category<<"] "<<message<<endl;
}

struct CommandResult {
    int exit_code;
    string output;
};

CommandResult execute_command(const string& command) {
    CommandResult result{};
    array<char,256> buffer{};
    string output;

#ifdef _WIN32
    string full_command="cmd /C "+command+" 2>&1";
#else
    string full_command=command+" 2>&1";
#endif

    FILE* pipe=popen(full_command.c_str(),"r");

    if(!pipe) {
        result.exit_code=-1;
        result.output="Unable to execute command";
        return result;
    }

    while(fgets(buffer.data(),buffer.size(),pipe)!=nullptr) {
        output+=buffer.data();
    }

    int status=pclose(pipe);

    result.exit_code=status;
    result.output=output;

    return result;
}

void run_command(const string& command,const string& category,const string& logfile) {
    log_message(category,"Executing command: "+command,logfile);

    CommandResult result=execute_command(command);

    if(!result.output.empty()) {
        log_message(category,result.output,logfile);
    }

    if(result.exit_code==0) {
        log_message(category,"Command completed successfully.",logfile);
    }
    else {
        log_message("ERROR","Command failed with exit code: "+to_string(result.exit_code),logfile);
    }
}

bool file_exists(const string& path) {
    try {
        return fs::exists(path);
    }
    catch(...) {
        return false;
    }
}

bool is_root_user() {
#ifdef _WIN32
    return false;
#else
    return geteuid()==0;
#endif
}

class BaseUpdater {
public:
    virtual ~BaseUpdater()=default;

    virtual void update(const string& logfile,bool dry_run)=0;

    virtual void update_firmware(const string& logfile,bool dry_run)=0;
};
void gather_system_info(const string& logfile){
    log_message("INFO","===== SYSTEM INFORMATION =====",logfile);
#ifdef _WIN32
    log_message("INFO","System: Windows",logfile);
    run_command("systeminfo","INFO",logfile);
    run_command("wmic cpu get NumberOfCores,NumberOfLogicalProcessors","INFO",logfile);
    run_command("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory","INFO",logfile);
    run_command("wmic logicaldisk get Name,Size,FreeSpace","INFO",logfile);
    run_command("ipconfig","INFO",logfile);
#elif defined(__APPLE__)
    log_message("INFO","System: macOS",logfile);
    run_command("sysctl -n machdep.cpu.brand_string","INFO",logfile);
    run_command("sysctl hw.physicalcpu hw.logicalcpu","INFO",logfile);
    run_command("vm_stat","INFO",logfile);
    run_command("df -h","INFO",logfile);
    run_command("ifconfig","INFO",logfile);
#elif defined(__linux__)
    log_message("INFO","System: Linux",logfile);
    run_command("lscpu","INFO",logfile);
    run_command("free -h","INFO",logfile);
    run_command("df -h","INFO",logfile);
    run_command("ip addr","INFO",logfile);
#else
    log_message("INFO","System: Unknown",logfile);
#endif
    log_message("INFO","===== END SYSTEM INFORMATION =====",logfile);
}
class OSXUpdater:public BaseUpdater{
public:
    void update(const string& logfile,bool dry_run) override{
        log_message("INFO","Starting macOS update...",logfile);
        if(dry_run){
            log_message("DRY-RUN","softwareupdate --list && softwareupdate -ia --verbose",logfile);
            return;
        }
        run_command("softwareupdate --list","INFO",logfile);
        run_command("softwareupdate -ia --verbose","INFO",logfile);
        log_message("INFO","macOS update completed.",logfile);
    }
    void update_firmware(const string& logfile,bool dry_run) override{
        log_message("INFO","Checking macOS firmware updates...",logfile);
        if(dry_run){
            log_message("DRY-RUN","softwareupdate --list",logfile);
            return;
        }
        run_command("softwareupdate --list","INFO",logfile);
        log_message("INFO","macOS firmware check completed.",logfile);
    }
};
class WindowsUpdater:public BaseUpdater{
public:
    void update(const string& logfile,bool dry_run) override{
        log_message("INFO","Starting Windows update...",logfile);
        string command="powershell -Command \"Get-WindowsUpdate -Install -AcceptAll\"";
        if(dry_run){
            log_message("DRY-RUN",command,logfile);
            return;
        }
        run_command(command,"INFO",logfile);
        log_message("INFO","Windows update completed.",logfile);
    }
    void update_firmware(const string& logfile,bool dry_run) override{
        log_message("INFO","Checking Windows firmware updates...",logfile);
        string command="powershell -Command \"Get-WindowsUpdate\"";
        if(dry_run){
            log_message("DRY-RUN",command,logfile);
            return;
        }
        run_command(command,"INFO",logfile);
        log_message("INFO","Windows firmware check completed.",logfile);
    }
};
class LinuxUpdater:public BaseUpdater{
private:
    bool command_exists(const string& command){
        if(command=="apt") return file_exists("/usr/bin/apt");
        if(command=="dnf") return file_exists("/usr/bin/dnf");
        if(command=="zypper") return file_exists("/usr/bin/zypper");
        if(command=="fwupdmgr") return file_exists("/usr/bin/fwupdmgr");
        return false;
    }
public:
    void update(const string& logfile,bool dry_run) override{
        log_message("INFO","Starting Linux update...",logfile);
        string command;
        if(command_exists("apt")){
            command="apt update && apt upgrade -y";
        }
        else if(command_exists("dnf")){
            command="dnf upgrade -y";
        }
        else if(command_exists("zypper")){
            command="zypper refresh && zypper update -y";
        }
        else{
            log_message("ERROR","No supported package manager found.",logfile);
            return;
        }
        if(!is_root_user()){
            command="sudo "+command;
            log_message("WARN","Running package update through sudo.",logfile);
        }
        if(dry_run){
            log_message("DRY-RUN",command,logfile);
            return;
        }
        run_command(command,"INFO",logfile);
        log_message("INFO","Linux update completed.",logfile);
    }
    void update_firmware(const string& logfile,bool dry_run) override{
        log_message("INFO","Checking Linux firmware updates...",logfile);
        if(!command_exists("fwupdmgr")){
            log_message("ERROR","fwupdmgr not found.",logfile);
            return;
        }
        string command="fwupdmgr get-updates && fwupdmgr update";
        if(!is_root_user()){
            command="sudo "+command;
        }
        if(dry_run){
            log_message("DRY-RUN",command,logfile);
            return;
        }
        run_command(command,"INFO",logfile);
        log_message("INFO","Linux firmware check completed.",logfile);
    }
};
class UpdaterManager{
private:
    unique_ptr<BaseUpdater> updater;
public:
    string detect_os(){
#ifdef _WIN32
        updater=make_unique<WindowsUpdater>();
        return "windows";
#elif defined(__APPLE__)
        updater=make_unique<OSXUpdater>();
        return "macos";
#elif defined(__linux__)
        updater=make_unique<LinuxUpdater>();
        return "linux";
#else
        throw runtime_error("Unsupported operating system");
#endif
    }
    void run(const string& logfile,bool dry_run){
        if(!updater){
            throw runtime_error("No updater available");
        }
        updater->update(logfile,dry_run);
        updater->update_firmware(logfile,dry_run);
    }
};
int main(int argc,char* argv[]){
    string log_filename="update_log.txt";
    bool dry_run=false;
    for(int i=1;i<argc;i++){
        string arg=argv[i];
        if(arg=="--dry-run"){
            dry_run=true;
        }
        else if(arg=="--log" && i+1<argc){
            log_filename=argv[++i];
        }
        else if(arg=="--help" || arg=="-h"){
            cout<<"Usage:\n";
            cout<<"  "<<argv[0]<<" [options]\n\n";
            cout<<"Options:\n";
            cout<<"  --dry-run        Show commands without executing updates\n";
            cout<<"  --log <file>     Set log filename\n";
            cout<<"  --help, -h       Show this help message\n";
            return 0;
        }
        else{
            cerr<<"Unknown option: "<<arg<<endl;
            return 1;
        }
    }
    try{
        log_message("INFO","===== UPDATE PROCESS STARTED =====",log_filename);
        if(dry_run){
            log_message("INFO","Running in dry-run mode.",log_filename);
        }
        gather_system_info(log_filename);
        UpdaterManager manager;
        string os_name=manager.detect_os();
        log_message("INFO","Detected OS: "+os_name,log_filename);
        manager.run(log_filename,dry_run);
        log_message("INFO","All update checks completed.",log_filename);
        cout<<"Update process completed. Log file: "<<log_filename<<endl;
    }
    catch(const exception& e){
        log_message("FATAL",e.what(),log_filename);
        cerr<<"Fatal error: "<<e.what()<<endl;
        return 1;
    }
    return 0;
}
