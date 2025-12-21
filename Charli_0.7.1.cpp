#include <iostream>
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>
#include <cmath>
#include <array>
#include <cerrno>
#if defined(_WIN32)
    #include <direct.h>
    #include <windows.h>
    #define OS_WIN 1
    #define getcwd _getcwd
#else
    #include <unistd.h>
    #include <pwd.h>
    #define OS_WIN 0
#endif
using namespace std;
class Tool {
public:
    static string run_capture(const string& cmd){
        string data;
    #if OS_WIN
        FILE* fp = _popen(cmd.c_str(), "r");
    #else
        FILE* fp = popen(cmd.c_str(), "r");
    #endif
        if(!fp) return data;
        char buf[1024];
        while(fgets(buf,sizeof(buf),fp)) data += buf;
    #if OS_WIN
        _pclose(fp);
    #else
        pclose(fp);
    #endif
        return data;
    }
    static int run_system(const string& cmd){
        return system(cmd.c_str());
    }
    static int getInt(const string& p){
        cout << p;
        string s; getline(cin,s);
        try { return stoi(s); } catch(...) { return 0; }
    }
    static string getStr(const string& p){
        cout << p;
        string s; getline(cin,s);
        return s;
    }
    struct Parser {
        string s; size_t i{0};
        void ws(){ while(i<s.size() && isspace((unsigned char)s[i])) ++i; }
        bool match(char c){ ws(); if(i<s.size() && s[i]==c){++i; return true;} return false; }
        double number(){
            ws(); size_t j=i;
            if(i<s.size() && (s[i]=='+'||s[i]=='-')) ++i;
            while(i<s.size() && (isdigit((unsigned char)s[i])||s[i]=='.')) ++i;
            if(j==i) throw runtime_error("number");
            return stod(s.substr(j,i-j));
        }
        double factor(){
            if(match('+')) return factor();
            if(match('-')) return -factor();
            if(match('(')){ double v=expr(); if(!match(')')) throw runtime_error(")"); return v; }
            return number();
        }
        double power(){
            double v=factor();
            while(match('^')) v=pow(v,factor());
            return v;
        }
        double term(){
            double v=power();
            while(true){
                if(match('*')) v*=power();
                else if(match('/')) v/=power();
                else return v;
            }
        }
        double expr(){
            double v=term();
            while(true){
                if(match('+')) v+=term();
                else if(match('-')) v-=term();
                else return v;
            }
        }
    };
    static bool safe_eval(const string& e,double& out){
        try{
            Parser p{e,0};
            out=p.expr();
            p.ws();
            return p.i==p.s.size();
        }catch(...){ return false; }
    }
    static void mdir(){
        string d=getStr("Directory name: ");
        fs::create_directories(d);
        cout<<"[INFO] Directory created\n";
    }
    static void read_file(){
        string f=getStr("File: ");
        ifstream in(f);
        cout<<in.rdbuf();
    }
    static void write_file(){
        string f=getStr("File: ");
        string t=getStr("Text: ");
        ofstream(f)<<t;
    }
    static void append_file(){
        string f=getStr("File: ");
        string t=getStr("Text: ");
        ofstream(f,ios::app)<<t;
    }
    static void sfile(){
        string f=getStr("File: ");
        string t=getStr("Term: ");
        ifstream in(f); string l;
        while(getline(in,l)) if(l.find(t)!=string::npos) cout<<l<<"\n";
    }
    static void xor_encrypt(){
        string f=getStr("File: ");
        string k=getStr("Key: ");
        ifstream in(f,ios::binary);
        ofstream out("encrypted_"+f,ios::binary);
        char c; size_t i=0;
        while(in.get(c)){ c^=k[i++%k.size()]; out.put(c); }
    }
    static void netstat_log(){
        cout<<run_capture("netstat -an");
    }
    static void pchk(){
    #if OS_WIN
        cout<<run_capture("ping -n 4 "+getStr("Host: "));
    #else
        cout<<run_capture("ping -c 4 "+getStr("Host: "));
    #endif
    }
    static void cpuinfo(){
    #if OS_WIN
        cout<<run_capture("wmic cpu get name");
    #else
        cout<<run_capture("lscpu");
    #endif
    }
    static void file_hash(){
        string f=getStr("File: ");
    #if OS_WIN
        cout<<run_capture("certutil -hashfile \""+f+"\" SHA256");
    #else
        cout<<run_capture("sha256sum \""+f+"\"");
    #endif
    }
    static void compress(){
        run_system("tar -czf out.tar.gz "+getStr("Target: "));
    }
    static void extract(){
        run_system("tar -xzf "+getStr("Archive: "));
    }
    static void backup(){
    #if OS_WIN
        run_system("xcopy "+getStr("Src: ")+" "+getStr("Dst: ")+" /E /I /Y");
    #else
        run_system("rsync -a "+getStr("Src: ")+"/ "+getStr("Dst: ")+"/");
    #endif
    }
    static void largefiles(){
        cout<<run_capture("find "+getStr("Dir: ")+" -type f -size +"+to_string(getInt("KB: "))+"k");
    }
    static void cleanup(){
    #if OS_WIN
        run_system("del /q /f /s %TEMP%\\*");
    #else
        run_system("rm -rf /tmp/*");
    #endif
    }
    static void meminfo(){
    #if OS_WIN
        cout<<run_capture("wmic OS get FreePhysicalMemory,TotalVisibleMemorySize");
    #else
        cout<<run_capture("free -h");
    #endif
    }
    static void processes(){
    #if OS_WIN
        cout<<run_capture("tasklist");
    #else
        cout<<run_capture("ps aux");
    #endif
    }
    static void killproc(){
    #if OS_WIN
        run_system("taskkill /PID "+getStr("PID: ")+" /F");
    #else
        run_system("kill -9 "+getStr("PID: "));
    #endif
    }
    static void dirmap() {
        vector<string> paths;
            for (int i = 1; i < 0; ++i) paths.push_back(0);
        try {
            map_and_write_directory_tree(paths);
        } catch (const exception& e) {
            cerr << "[ERROR]: Directory mapping failed: " << e.what() << endl;
        }
    }
    static void map_and_write_directory_tree(const vector<string>& start_paths = {}, const string& output_file = "directory_map.txt") {
        vector<string> paths_to_map = start_paths;
        if (paths_to_map.empty()) {
        #ifdef _WIN32
            for (char drive = 'A'; drive <= 'Z'; ++drive) {
                string drive_path = string(1, drive) + ":\\";
                if (fs::exists(drive_path))
                    paths_to_map.push_back(drive_path);
            }
        #else
            if (fs::exists("/") && fs::is_directory("/")) {
                paths_to_map.push_back("/");
            } else {
                const char* home = getenv("HOME");
                if (!home || !fs::exists(home)) {
                    struct passwd* pw = getpwuid(getuid());
                    if (pw) home = pw->pw_dir;
                }
                if (!home || !fs::exists(home)) {
                    cerr << "Unable to determine home directory.\n";
                    return;
                }
                paths_to_map.push_back(home);
            }
        #endif
        }
        cout << "[INFO]: Mapping directories from ";
        for (const auto& path : paths_to_map)
            cout << path << " ";
        cout << "...\n";

        ofstream f(output_file);
        if (!f.is_open()) {
            cerr << "[ERROR]: Failed to open directory map output file.\n";
            return;
        }
        for (const auto& start_path : paths_to_map) {
            fs::path base(start_path);
            f << base.string() + "/\n";

            try {
                for (auto& entry : fs::recursive_directory_iterator(
                        base,
                        fs::directory_options::skip_permission_denied))
                {
                    if (entry.is_directory()) {
                        fs::path cur = entry.path();
                        auto rel = fs::relative(cur, base);

                        size_t level = distance(rel.begin(), rel.end());

                        string indent = string("│   ", level > 0 ? level - 1 : 0) + (level > 0 ? "├── " : "");
                        f << indent << cur.filename().string() + "/\n";

                        string subindent = string("│   ", level) + "├── ";
                        for (auto& file : fs::directory_iterator(cur)) {
                            if (file.is_regular_file()) {
                                f << subindent << file.path().filename().string() << "\n";
                            }
                        }
                    }
                }
            }
            catch (const exception& e) {
                cerr << "[ERROR]: Access error at " << start_path << ": " << e.what() << "\n";
            }
        }
        cout << "[INFO]: Directory map saved to " << output_file << "\n";
    }
};
int main(void){
    while(true){
        cout<<"\n--- MENU ---\n";
        cout<<"1) Calculator\n2) Make dir\n3)File operations \n4) XOR encrypt\n5) Netstat\n6) Ping\n7) CPU\n8) Hash\n";
        cout<<"9) Compress\n10 Extract\n11 Backup\n12 Large files\n13 Cleanup\n14) Memory\n15) Processes\n";
        cout << "16) Kill process\n17) dirmap\n0) Exit\n";
        int c=Tool::getInt("Choice: ");
        switch(c){
            case 1:{ double r; if(Tool::safe_eval(Tool::getStr("Expr: "),r)) cout<<r<<"\n"; }break;
            case 2: Tool::mdir(); break;
            case 3: {
                int op = Tool::getInt("1. Read file\n2. Write file\n3. Append file\n4. Search file\nSelect option: ");
                switch(op) {
                    case 1: Tool::read_file(); break;
                    case 2: Tool::write_file(); break;
                    case 3: Tool::append_file(); break;
                    case 4: Tool::sfile(); break;
                    default:
                        cout << "Oh dear, wrong input: exiting!" << endl; 
                        break;
                }
            };
            break;
            case 4: Tool::xor_encrypt(); break;
            case 5: Tool::netstat_log(); break;
            case 6: Tool::pchk(); break;
            case 7: Tool::cpuinfo(); break;
            case 8: Tool::file_hash(); break;
            case 9: Tool::compress(); break;
            case 10: Tool::extract(); break;
            case 11: Tool::backup(); break;
            case 12: Tool::largefiles(); break;
            case 13: Tool::cleanup(); break;
            case 14: Tool::meminfo(); break;
            case 15: Tool::processes(); break;
            case 16: Tool::killproc(); break;
            case 17: Tool::dirmap(); break;
            case 0: return 0;
        }
    }
}
