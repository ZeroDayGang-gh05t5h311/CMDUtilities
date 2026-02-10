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
#if defined(_WIN32)
    #include <windows.h>
    #define OS_WIN 1
#else
    #include <unistd.h>
    #include <pwd.h>
    #define OS_WIN 0
#endif
namespace fs = std::filesystem;
using namespace std;
class Input {
public:
    static string str(const string& p) {
        cout << p;
        string s;
        getline(cin, s);
        return s;
    }
    static int integer(const string& p) {
        try {
            return stoi(str(p));
        } catch (...) {
            return 0;
        }
    }
    static bool safe(const string& s) {
        for (char c : s)
            if (!(isalnum((unsigned char)c) || c=='/' || c=='_' || c=='.' || c=='-' || c==':'))
                return false;
        return true;
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
        array<char,1024> buf{};
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
    };
};
class Calculator {
    struct Parser {
        string s; size_t i{0};
        void ws(){ while(i<s.size() && isspace((unsigned char)s[i])) ++i; }
        bool match(char c){ ws(); if(i<s.size() && s[i]==c){++i; return true;} return false; }
        double number(){
            ws(); size_t j=i;
            if(i<s.size() && (s[i]=='+'||s[i]=='-')) ++i;
            while(i<s.size() && (isdigit((unsigned char)s[i])||s[i]=='.')) ++i;
            if(j==i) throw runtime_error("num");
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
            if(match('^')) v=pow(v,power());
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
public:
    static bool eval(const string& e, double& out) {
        try {
            Parser p{e,0};
            out = p.expr();
            p.ws();
            return p.i == p.s.size();
        } catch (...) {
            return false;
        }
    }
};
class FileOps {
public:
    static void mkdir() {
        fs::create_directories(Input::str("Directory name: "));
        cout << "[INFO] Directory created\n";
    }

    static void read() {
        ifstream f(Input::str("File: "));
        if(!f){ cerr<<"[ERROR] Open failed\n"; return; }
        cout << f.rdbuf();
    }
    static void write(bool append=false) {
        string f = Input::str("File: ");
        string t = Input::str("Text: ");
        ofstream o(f, append ? ios::app : ios::trunc);
        if(!o){ cerr<<"[ERROR] Write failed\n"; return; }
        o << t;
    }
    static void search() {
        ifstream f(Input::str("File: "));
        if(!f){ cerr<<"[ERROR]\n"; return; }
        string term = Input::str("Term: "), line;
        while(getline(f,line))
            if(line.find(term)!=string::npos)
                cout<<line<<"\n";
    }
    static void xor_encrypt() {
        string f = Input::str("File: ");
        string k = Input::str("Key: ");
        if(k.empty()){ cerr<<"[ERROR] Empty key\n"; return; }
        ifstream in(f, ios::binary);
        ofstream out("encrypted_"+f, ios::binary);
        if(!in||!out){ cerr<<"[ERROR] File error\n"; return; }
        char c; size_t i=0;
        while(in.get(c)){
            c ^= k[i++ % k.size()];
            out.put(c);
        }
    }
};
class SystemOps {
public:
    static void netstat() {
        cout << Command::capture({"netstat","-an"});
    }
    static void ping() {
        string h = Input::str("Host: ");
        if(!Input::safe(h)){ cerr<<"[ERROR]\n"; return; }
#if OS_WIN
        cout << Command::capture({"ping","-n","4",h});
#else
        cout << Command::capture({"ping","-c","4",h});
#endif
    }
    static void cpu() {
#if OS_WIN
        cout << Command::capture({"wmic","cpu","get","name"});
#else
        cout << Command::capture({"lscpu"});
#endif
    }
    static void hash() {
        string f = Input::str("File: ");
#if OS_WIN
        cout << Command::capture({"certutil","-hashfile",f,"SHA256"});
#else
        cout << Command::capture({"sha256sum",f});
#endif
    }
    static void compress() {
        Command::run({"tar","-czf","out.tar.gz",Input::str("Target: ")});
    }

    static void extract() {
        Command::run({"tar","-xzf",Input::str("Archive: ")});
    }
    static void backup() {
#if OS_WIN
        Command::run({"xcopy",Input::str("Src: "),Input::str("Dst: "),"/E","/I","/Y"});
#else
        Command::run({"rsync","-a",Input::str("Src: ")+"/",Input::str("Dst: ")+"/"});
#endif
    }
    static void largefiles() {
        cout << Command::capture({
            "find",
            Input::str("Dir: "),
            "-type","f","-size","+"+to_string(Input::integer("KB: "))+"k"
        });
    }
    static void cleanup() {
#if OS_WIN
        Command::run({"cmd","/c","del","/q","/f","/s","%TEMP%\\*"});
#else
        Command::run({"rm","-rf","/tmp/*"});
#endif
    }
    static void meminfo() {
#if OS_WIN
        cout << Command::capture({"wmic","OS","get","FreePhysicalMemory,TotalVisibleMemorySize"});
#else
        cout << Command::capture({"free","-h"});
#endif
    }
    static void processes() {
#if OS_WIN
        cout << Command::capture({"tasklist"});
#else
        cout << Command::capture({"ps","aux"});
#endif
    }
    static void killproc() {
        string pid = Input::str("PID: ");
        if(!Input::safe(pid)){ cerr<<"[ERROR]\n"; return; }
#if OS_WIN
        Command::run({"taskkill","/PID",pid,"/F"});
#else
        Command::run({"kill","-9",pid});
#endif
    }
};
class DirectoryMap {
public:
    static void run() {
        ofstream f("directory_map.txt");
        if(!f){ cerr<<"[ERROR]\n"; return; }
        walk(fs::current_path(), f, 0);
        cout<<"[INFO] Directory map saved\n";
    }
private:
    static void walk(const fs::path& p, ofstream& f, int d) {
        f << string(d*2,' ') << p.filename().string() << "/\n";
        for(auto& e: fs::directory_iterator(p, fs::directory_options::skip_permission_denied)){
            if(e.is_directory())
                walk(e.path(), f, d+1);
            else
                f << string(d*2+2,' ') << e.path().filename().string() << "\n";
        };
    };
};
static void helpmenu() {
          cout<<"\n--- MENU ---\n";
        cout<<"1) Calculator\n2) Make dir\n3) File ops\n4) XOR encrypt\n5) Netstat\n6) Ping\n7) CPU\n8) Hash\n";
        cout<<"9) Compress\n10) Extract\n11) Backup\n12) Large files\n13) Cleanup\n14) Memory\n15) Processes\n";
        cout<<"16) Kill process\n17) dirmap\n18) help(this text)\n0 Exit\n";
}
int main() {
     cout<<"\n--- MENU ---\n";
        cout<<"1) Calculator\n2) Make dir\n3) File ops\n4) XOR encrypt\n5) Netstat\n6) Ping\n7) CPU\n8) Hash\n";
        cout<<"9) Compress\n10) Extract\n11) Backup\n12) Large files\n13) Cleanup\n14) Memory\n15) Processes\n";
        cout<<"16) Kill process\n17) dirmap\n18) help(this text)\n0 Exit\n";
    while(true){
        switch(Input::integer("Choice: ")) {
            case 1:{ double r; if(Calculator::eval(Input::str("Expr: "),r)) cout<<r<<"\n"; } break;
            case 2: FileOps::mkdir(); break;
            case 3: {
                int o=Input::integer("1 Read 2 Write 3 Append 4 Search: ");
                if(o==1) FileOps::read();
                else if(o==2) FileOps::write(false);
                else if(o==3) FileOps::write(true);
                else if(o==4) FileOps::search();
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
            case 0: cout << "Not an option: exiting!"; return 0; 
        }
    }
}; //g++ Charli.cpp 
