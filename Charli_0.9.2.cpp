#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>
#include <array>
#include <stdexcept>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <regex>
#if defined(_WIN32)
    #include <windows.h>
    #define OS_WIN 1
    #define OS_MAC 0
#else
    #include <unistd.h>
    #include <pwd.h>
    #if defined(__APPLE__)
        #define OS_MAC 1
    #else
        #define OS_MAC 0
    #endif
    #define OS_WIN 0
#endif
namespace fs = std::filesystem;
using namespace std;
class Input {
public:
    static string str(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }
    static int integer(const string& prompt) {
        try {
            return stoi(str(prompt));
        } catch (...) {
            cerr << "[ERROR] Invalid number\n";
            return 0;
        }
    }
    static bool safe(const string& str) {
        return all_of(str.begin(), str.end(), [](char c) {
            return isalnum((unsigned char)c) || c=='/'||c=='_'||c=='.'||c=='-'||c==':';
        });
    }
    static bool isValidHost(const string& host) {
        regex pattern(R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$)");
        return regex_match(host, pattern);
    }
};
class Command {
public:
    static string capture(const vector<string>& args) {
        string cmd;
        for (const auto& a : args) {
            if (!Input::safe(a)) throw runtime_error("Unsafe argument");
            cmd += a + " ";
        }
        array<char, 1024> buf{};
        string out;
#if OS_WIN
        FILE* fp = _popen(cmd.c_str(), "r");
#else
        FILE* fp = popen(cmd.c_str(), "r");
#endif
        if (!fp) return "";
        while (fgets(buf.data(), buf.size(), fp))
            out += buf.data();
#if OS_WIN
        _pclose(fp);
#else
        pclose(fp);
#endif
        return out;
    }
    static void run(const vector<string>& args) {
        capture(args);
    }
};
class Calculator {
    struct Parser {
        string s;
        size_t i{0};
        void ws() { while (i<s.size() && isspace((unsigned char)s[i])) ++i; }
        bool match(char c) {
            ws();
            if (i<s.size() && s[i]==c) { ++i; return true; }
            return false;
        }
        double number() {
            ws();
            size_t j=i;
            if (i<s.size() && (s[i]=='+'||s[i]=='-')) ++i;
            while (i<s.size() && (isdigit((unsigned char)s[i])||s[i]=='.')) ++i;
            if (j==i) throw runtime_error("num");
            return stod(s.substr(j,i-j));
        }
        double factor() {
            if (match('+')) return factor();
            if (match('-')) return -factor();
            if (match('(')) {
                double v=expr();
                if (!match(')')) throw runtime_error(")");
                return v;
            }
            return number();
        }
        double power() {
            double v=factor();
            if (match('^')) v=pow(v,power());
            return v;
        }
        double term() {
            double v=power();
            while (true) {
                if (match('*')) v*=power();
                else if (match('/')) v/=power();
                else return v;
            }
        }
        double expr() {
            double v=term();
            while (true) {
                if (match('+')) v+=term();
                else if (match('-')) v-=term();
                else return v;
            }
        }
    };
public:
    static bool eval(const string& expr, double& out) {
        try {
            Parser p{expr,0};
            out=p.expr();
            p.ws();
            return p.i==p.s.size();
        } catch (...) {
            return false;
        }
    }
};
class FileOps {
public:
    static bool openFile(ifstream& f,const string& filename){
        f.open(filename);
        if(!f){ cerr<<"[ERROR] Open failed\n"; return false;}
        return true;
    }
    static bool openFile(ofstream& f,const string& filename,ios::openmode mode=ios::trunc){
        f.open(filename,mode);
        if(!f){ cerr<<"[ERROR] Write failed\n"; return false;}
        return true;
    }
    static void mkdir(){
        string dir=Input::str("Directory name: ");
        if(fs::exists(dir)) cout<<"[INFO] Exists\n";
        else { fs::create_directories(dir); cout<<"[INFO] Created\n"; }
    }
    static void read(){
        string file=Input::str("File: ");
        ifstream f;
        if(openFile(f,file)) cout<<f.rdbuf();
    }
    static void write(bool append=false){
        string file=Input::str("File: ");
        string text=Input::str("Text: ");
        ofstream out;
        if(openFile(out,file,append?ios::app:ios::trunc))
            out<<text;
    }
    static void search(){
        string file=Input::str("File: ");
        ifstream f;
        if(!openFile(f,file)) return;
        string term=Input::str("Term:"), line;
        while(getline(f,line))
            if(line.find(term)!=string::npos)
                cout<<line<<"\n";
    }
    static void xor_encrypt(){
        string file=Input::str("File: ");
        string key=Input::str("Key: ");
        ifstream in(file,ios::binary);
        ofstream out("encrypted_"+file,ios::binary);
        char c; size_t i=0;
        while(in.get(c)){
            c^=key[i++%key.size()];
            out.put(c);
        }
    }
};
class SystemOps {
public:
    static void netstat() {
        cout << Command::capture({ "netstat", "-an" });
    }
    static void ping() {
        string host = Input::str("Host: ");
        if (!Input::isValidHost(host)) {
            cerr << "[ERROR] Invalid host\n";
            return;
        }
        vector<string> cmd = { "ping" };
        if (OS_WIN) {
            cmd.push_back("-n");
            cmd.push_back("4");
        } else {
            cmd.push_back("-c");
            cmd.push_back("4");
        }
        cmd.push_back(host);
        cout << Command::capture(cmd);
    }
    static void cpu() {
#if OS_WIN
        cout << Command::capture({ "wmic", "cpu", "get", "name" });
#elif OS_MAC
        cout << Command::capture({ "sysctl", "-n", "machdep.cpu.brand_string" });
#else
        cout << Command::capture({ "lscpu" });
#endif
    }
    static void hash() {
        string file = Input::str("File: ");
#if OS_WIN
        cout << Command::capture({ "certutil", "-hashfile", file, "SHA256" });
#elif OS_MAC
        cout << Command::capture({ "shasum", "-a", "256", file });
#else
        cout << Command::capture({ "sha256sum", file });
#endif
    }
    static void compress() {
        Command::run({ "tar", "-czf", "out.tar.gz", Input::str("Target: ") });
    }
    static void extract() {
        Command::run({ "tar", "-xzf", Input::str("Archive: ") });
    }
    static void backup() {
#if OS_WIN
        Command::run({ "xcopy", Input::str("Src: "), Input::str("Dst: "), "/E", "/I", "/Y" });
#else
        Command::run({ "rsync", "-a", Input::str("Src: ") + "/", Input::str("Dst: ") + "/" });
#endif
    }
    static void largefiles() {
        cout << Command::capture({
            "find",
            Input::str("Dir: "),
            "-type", "f",
            "-size", "+" + to_string(Input::integer("KB: ")) + "k"
        });
    }
    static void cleanup() {
#if OS_WIN
        Command::run({ "cmd", "/c", "del", "/q", "/f", "/s", "%TEMP%\\*" });
#elif OS_MAC
        Command::run({ "rm", "-rf", "/tmp/*" });
#else
        Command::run({ "rm", "-rf", "/tmp/*" });
#endif
    }
    static void meminfo() {
#if OS_WIN
        cout << Command::capture({ "wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize" });
#elif OS_MAC
        cout << Command::capture({ "vm_stat" });
#else
        cout << Command::capture({ "free", "-h" });
#endif
    }
    static void processes() {
#if OS_WIN
        cout << Command::capture({ "tasklist" });
#else
        cout << Command::capture({ "ps", "aux" });
#endif
    }
    static void killproc() {
        string pid = Input::str("PID: ");
        if (!Input::safe(pid)) {
            cerr << "[ERROR] Invalid PID\n";
            return;
        }

#if OS_WIN
        Command::run({ "taskkill", "/PID", pid, "/F" });
#else
        Command::run({ "kill", "-9", pid });
#endif
    }
};
class DirectoryMap {
public:
    static void run() {
        ofstream f("directory_map.txt");
        if (!f) {
            cerr << "[ERROR] Failed to create file\n";
            return;
        }
        walk(fs::current_path(), f, 0);
        cout << "[INFO] Directory map saved\n";
    }
private:
    static void walk(const fs::path& p, ofstream& f, int depth) {
        f << string(depth * 2, ' ') << p.filename().string() << "/\n";

        for (auto& entry : fs::directory_iterator(p, fs::directory_options::skip_permission_denied)) {
            if (entry.is_directory())
                walk(entry.path(), f, depth + 1);
            else
                f << string(depth * 2 + 2, ' ') << entry.path().filename().string() << "\n";
        }
    }
};
static void printMenu() {
    cout << "\n--- MENU ---\n";
    cout << "1) Calculator\n2) Make dir\n3) File ops\n4) XOR encrypt\n5) Netstat\n6) Ping\n7) CPU\n8) Hash\n";
    cout << "9) Compress\n10) Extract\n11) Backup\n12) Large files\n13) Cleanup\n14) Memory\n15) Processes\n";
    cout << "16) Kill process\n17) dirmap\n18) help(this text)\n0 Exit\n";
}
static void helpmenu() {
    printMenu();
}
int main() {
    printMenu();
    int choice;
    do {
        choice = Input::integer("Choice: ");
        if (choice < 0 || choice > 18) {
            cerr << "[ERROR] Invalid choice\n";
            continue;
        }
        switch (choice) {
            case 1: {
                double result;
                if (Calculator::eval(Input::str("Expr: "), result))
                    cout << result << "\n";
                else
                    cerr << "[ERROR] Invalid expression\n";
            } break;
            case 2: FileOps::mkdir(); break;
            case 3: {
                int option = Input::integer("1 Read 2 Write 3 Append 4 Search: ");
                if (option == 1) FileOps::read();
                else if (option == 2) FileOps::write(false);
                else if (option == 3) FileOps::write(true);
                else if (option == 4) FileOps::search();
            } break;
            case 4: FileOps::xor_encrypt(); break;
            case 5: SystemOps::netstat(); break;
            case 6: SystemOps::ping(); break;
            case 7: SystemOps::cpu(); break;
            case 8: SystemOps::hash(); break;
            case 9: SystemOps::compress(); break;
            case 10: SystemOps::extract(); break;
            case 11: SystemOps::backup(); break;
            case 12: SystemOps::largefiles(); break;
            case 13: SystemOps::cleanup(); break;
            case 14: SystemOps::meminfo(); break;
            case 15: SystemOps::processes(); break;
            case 16: SystemOps::killproc(); break;
            case 17: DirectoryMap::run(); break;
            case 18: helpmenu(); break;
            case 0: cout << "OK, see you later.\n"; return 0;
        }
    } while (choice != 0 || "exit");
    return 0;
}
