#include <iostream>
#include <string>
#include <memory>
#include <fstream>
#include <ctime>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <array>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
using namespace std;
namespace fs=std::filesystem;
mutex logMutex;
string logFilename="update_log.txt";
bool dryRun=false;
bool firmwareMode=false;
void logMessage(const string& category,const string& message){
    lock_guard<mutex> guard(logMutex);
    ofstream logFile(logFilename,ios::app);
    if(!logFile){
        cerr<<"Error opening log file!"<<endl;
        return;
    }
    time_t now=time(nullptr);
    char timeStr[100]{};
    tm timeInfo{};
#ifdef _WIN32
    localtime_s(&timeInfo,&now);
#else
    localtime_r(&now,&timeInfo);
#endif
    strftime(timeStr,sizeof(timeStr),"%Y-%m-%d %H:%M:%S",&timeInfo);
    logFile<<"["<<timeStr<<"] ["<<category<<"] "<<message<<endl;
}
struct CommandResult{
    int exitCode;
    string output;
};
CommandResult executeCommand(const string& command){
    CommandResult result{};
    if(dryRun){
        result.exitCode=0;
        result.output="DRY-RUN: "+command;
        return result;
    }
    array<char,256> buffer{};
    string output;
#ifdef _WIN32
    string shellCommand="cmd /C "+command+" 2>&1";
#else
    string shellCommand=command+" 2>&1";
#endif
    FILE* pipe=popen(shellCommand.c_str(),"r");
    if(!pipe){
        result.exitCode=-1;
        result.output="Failed to execute command";
        return result;
    }
    while(fgets(buffer.data(),buffer.size(),pipe)!=nullptr){
        output+=buffer.data();
    }
    result.exitCode=pclose(pipe);
    result.output=output;
    return result;
}
bool runCommand(const string& category,const string& command){
    logMessage(category,"Executing: "+command);
    CommandResult result=executeCommand(command);
    if(!result.output.empty()){
        logMessage(category,result.output);
    }
    if(result.exitCode!=0){
        logMessage("ERROR","Command failed: "+to_string(result.exitCode));
        return false;
    }
    return true;
}
bool commandExists(const string& command){
#ifdef _WIN32
    string test="where "+command+" > nul 2>&1";
#else
    string test="command -v "+command+" > /dev/null 2>&1";
#endif
    return system(test.c_str())==0;
}
bool fileExists(const string& path){
    try{
        return fs::exists(path);
    }
    catch(...){
        return false;
    }
}
string trimQuotes(const string& value){
    if(value.size()>1&&value.front()=='"'&&value.back()=='"'){
        return value.substr(1,value.size()-2);
    }
    return value;
}
bool isRoot(){
#ifdef _WIN32
    return false;
#else
    return geteuid()==0;
#endif
}
class OSUpdater{
public:
    virtual ~OSUpdater()=default;
    virtual void checkForUpdates()=0;
    virtual void performUpdate()=0;
    virtual void handleDependencies()=0;
    virtual void updateFirmware()=0;
    virtual void updateCache()=0;
    virtual void gatherSystemInfo()=0;
};
class OSXUpdater:public OSUpdater{
private:
    void log(const string& message){
        logMessage("macOS",message);
    }
public:
    void checkForUpdates() override{
        log("Checking for macOS updates...");
        runCommand("macOS","softwareupdate -l");
    }
    void performUpdate() override{
        log("Installing macOS updates...");
        runCommand("macOS","softwareupdate --install --all");
        log("macOS update process completed.");
    }
    void handleDependencies() override{
        log("Checking application dependencies...");
        if(commandExists("brew")){
            runCommand("macOS","brew update");
            runCommand("macOS","brew upgrade");
        }
        else{
            log("Homebrew not installed, skipping dependency update.");
        }
    }
    void updateFirmware() override{
        if(!firmwareMode){
            log("Firmware updates skipped. Use --firmware to enable.");
            return;
        }
        log("Checking macOS firmware updates...");
        runCommand("macOS","softwareupdate --list");
    }
    void updateCache() override{
        log("Refreshing macOS update cache...");
        runCommand("macOS","softwareupdate --list");
    }
    void gatherSystemInfo() override{
        log("Gathering macOS system information...");
        runCommand("macOS","system_profiler SPHardwareDataType");
        runCommand("macOS","system_profiler SPSoftwareDataType");
        runCommand("macOS","system_profiler SPStorageDataType");
        runCommand("macOS","diskutil list");
        if(commandExists("brew")){
            runCommand("macOS","brew list --versions");
        }
        else{
            log("Homebrew unavailable.");
        }
    }
};class LinuxUpdater:public OSUpdater{
private:
    string distro;
    void log(const string& message){
        logMessage("Linux",message);
    }
    bool has(const string& command){
        return commandExists(command);
    }
    bool runPackageCommand(const string& command){
        string finalCommand=command;
        if(!isRoot()){
            finalCommand="sudo "+finalCommand;
        }
        return runCommand("Linux",finalCommand);
    }
public:
    LinuxUpdater(const string& distroName):distro(distroName){}
    void checkForUpdates() override{
        log("Checking updates for "+distro+"...");
        if((distro.find("Ubuntu")!=string::npos)||(distro.find("Debian")!=string::npos)||(distro.find("Mint")!=string::npos)){
            if(!has("apt-get")){
                log("apt-get unavailable.");
                return;
            }
            runPackageCommand("apt-get update");
        }
        else if((distro.find("Fedora")!=string::npos)||(distro.find("Red")!=string::npos)||(distro.find("CentOS")!=string::npos)){
            if(!has("dnf")){
                log("dnf unavailable.");
                return;
            }
            runPackageCommand("dnf check-update");
        }
        else if(distro.find("Arch")!=string::npos){
            if(!has("pacman")){
                log("pacman unavailable.");
                return;
            }
            runPackageCommand("pacman -Sy");
        }
        else{
            log("Unsupported Linux distribution.");
        }
    }
    void performUpdate() override{
        log("Performing update for "+distro+"...");
        if((distro.find("Ubuntu")!=string::npos)||(distro.find("Debian")!=string::npos)||(distro.find("Mint")!=string::npos)){
            if(has("apt-get")){
                runPackageCommand("apt-get upgrade -y");
            }
        }
        else if((distro.find("Fedora")!=string::npos)||(distro.find("Red")!=string::npos)||(distro.find("CentOS")!=string::npos)){
            if(has("dnf")){
                runPackageCommand("dnf upgrade -y");
            }
        }
        else if(distro.find("Arch")!=string::npos){
            if(has("pacman")){
                runPackageCommand("pacman -Syu --noconfirm");
            }
        }
    }
    void handleDependencies() override{
        log("Handling dependencies...");
        if(distro.find("Ubuntu")!=string::npos||distro.find("Debian")!=string::npos||distro.find("Mint")!=string::npos){
            if(has("apt-get")){
                runPackageCommand("apt-get autoremove -y");
                runPackageCommand("apt-get dist-upgrade -y");
            }
        }
        else if(distro.find("Fedora")!=string::npos||distro.find("Red")!=string::npos||distro.find("CentOS")!=string::npos){
            if(has("dnf")){
                runPackageCommand("dnf distro-sync -y");
            }
        }
        else if(distro.find("Arch")!=string::npos){
            if(has("pacman")){
                runPackageCommand("pacman -S archlinux-keyring --noconfirm");
            }
        }
    }
    void updateFirmware() override{
        if(!firmwareMode){
            log("Firmware updates disabled. Use --firmware to enable.");
            return;
        }
        log("Checking firmware updates...");
        if(!has("fwupdmgr")){
            log("fwupdmgr unavailable.");
            return;
        }
        string command="fwupdmgr refresh && fwupdmgr update";
        if(!isRoot()){
            command="sudo "+command;
        }
        runCommand("Linux",command);
    }
    void updateCache() override{
        log("Refreshing package cache...");
        if(distro.find("Ubuntu")!=string::npos||distro.find("Debian")!=string::npos||distro.find("Mint")!=string::npos){
            if(has("apt-get")){
                runPackageCommand("apt-get update");
            }
        }
        else if(distro.find("Fedora")!=string::npos||distro.find("Red")!=string::npos||distro.find("CentOS")!=string::npos){
            if(has("dnf")){
                runPackageCommand("dnf makecache");
            }
        }
        else if(distro.find("Arch")!=string::npos){
            if(has("pacman")){
                runPackageCommand("pacman -Sy");
            }
        }
    }
    void gatherSystemInfo() override{
        log("Gathering Linux system information...");
        runCommand("Linux","uname -a");
        runCommand("Linux","lscpu");
        runCommand("Linux","free -h");
        runCommand("Linux","lsblk");
        runCommand("Linux","df -h");
        runCommand("Linux","cat /etc/os-release");
        runCommand("Linux","ip addr");
        runCommand("Linux","lspci");
        if(has("fwupdmgr")){
            runCommand("Linux","fwupdmgr get-devices");
        }
    }
};
class UpdaterManager{
private:
    unique_ptr<OSUpdater> updater;
    string detectLinuxDistro(){
        ifstream file("/etc/os-release");
        string line;
        while(getline(file,line)){
            if(line.find("NAME=")==0){
                return trimQuotes(line.substr(5));
            }
        }
        return "Linux";
    }
public:
    void detectOS(){
#ifdef _WIN32
        updater=make_unique<WindowsUpdater>();
        logMessage("OS","Windows detected.");
#elif defined(__APPLE__)
        updater=make_unique<OSXUpdater>();
        logMessage("OS","macOS detected.");
#elif defined(__linux__)
        string distro=detectLinuxDistro();
        updater=make_unique<LinuxUpdater>(distro);
        logMessage("OS","Linux detected: "+distro);
#else
        throw runtime_error("Unsupported operating system.");
#endif
    }
    void gatherSystemInfo(){
        if(updater){
            updater->gatherSystemInfo();
        }
        else{
            logMessage("ERROR","No updater available.");
        }
    }
    void performUpdate(){
        if(!updater){
            logMessage("ERROR","No updater available.");
            return;
        }
        try{
            updater->updateCache();
            updater->checkForUpdates();
            updater->performUpdate();
            updater->handleDependencies();
            updater->updateFirmware();
        }
        catch(const exception& e){
            logMessage("ERROR",string("Update failed: ")+e.what());
        }
    }
};
void printHelp(){
    cout<<"Usage:"<<endl;
    cout<<"  updater [options]"<<endl;
    cout<<endl;
    cout<<"Options:"<<endl;
    cout<<"  -r, --run             Run updater"<<endl;
    cout<<"  --dry-run             Show commands without executing"<<endl;
    cout<<"  --firmware            Enable firmware updates"<<endl;
    cout<<"  --log <file>          Select log file"<<endl;
    cout<<"  -h, --help            Show help"<<endl;
}
int main(int argc,char* argv[]){
    bool run=false;
    for(int i=1;i<argc;i++){
        string arg=argv[i];
        if(arg=="-r"||arg=="--run"){
            run=true;
        }
        else if(arg=="--dry-run"){
            dryRun=true;
        }
        else if(arg=="--firmware"){
            firmwareMode=true;
        }
        else if(arg=="--log"&&i+1<argc){
            logFilename=argv[++i];
        }
        else if(arg=="-h"||arg=="--help"){
            printHelp();
            return 0;
        }
        else{
            cout<<"Unknown option: "<<arg<<endl;
            printHelp();
            return 1;
        }
    }
    if(!run){
        printHelp();
        return 0;
    }
    try{
        logMessage("INFO","===== UPDATE PROCESS STARTED =====");
        if(dryRun){
            logMessage("INFO","Dry-run mode enabled.");
        }
        if(firmwareMode){
            logMessage("INFO","Firmware updates enabled.");
        }
        UpdaterManager manager;
        manager.detectOS();
        manager.gatherSystemInfo();
        manager.performUpdate();
        logMessage("INFO","===== UPDATE PROCESS COMPLETED =====");
        cout<<"Update process completed. Log: "<<logFilename<<endl;
    }
    catch(const exception& e){
        logMessage("FATAL",e.what());
        cerr<<"Fatal error: "<<e.what()<<endl;
        return 1;
    }
    return 0;
}
