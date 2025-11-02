#include <bits/stdc++.h>
#include <iostream>
#include <fstream>
#if __has_include(<filesystem>)
  #include <filesystem>
  namespace fs = std::filesystem;
#endif
#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif
#include <future>  // Added for parallelism
#include <mutex>
#include <thread>
#include <chrono>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>
#include <vector>
#include <regex>
#include <algorithm>
#include <set>
using namespace std;
#ifdef _WIN32
#define OS_WIN 1
#else
#define OS_WIN 0
#endif
// -------- Command runner --------
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
        int rc = system(cmd.c_str());
        if(rc != 0) cerr << "[ERROR] Command failed: " << cmd << " (rc=" << rc << ")\n";
        return rc;
    }
    static int getInt(const string& prompt){
        cout << prompt;
        string s; getline(cin, s);
        try{ return stoi(s); }catch(...){ return 0; }
    }
    static string getStr(const string& prompt){
        cout << prompt;
        string s; getline(cin, s);
        return s;
    }
    /* If you want to modify this program ^^ these functions are a godsend ^^"
     -------- SafeCalc -------- */
    struct Parser{
        string s; size_t i{0};
        void ws(){ while(i<s.size() && isspace((unsigned char)s[i])) ++i; }
        bool match(char c){ ws(); if(i<s.size() && s[i]==c){ ++i; return true;} return false; }
        double number(){
            ws();
            size_t j=i;
            if(i<s.size() && (s[i]=='+'||s[i]=='-')) ++i;
            while(i<s.size() && (isdigit((unsigned char)s[i]) || s[i]=='.')) ++i;
            if(j==i) throw runtime_error("expected number");
            return stod(s.substr(j,i-j));
        }
        double expr(){ return addsub(); }
        double factor(){
            ws();
            if(match('+')) return factor();
            if(match('-')) return -factor();
            if(match('(')){ double v=expr(); if(!match(')')) throw runtime_error("missing ')'"); return v; }
            return number();
        }
        double power(){
            double v=factor(); ws();
            while(match('^')){ double r=factor(); v = pow(v,r); ws(); }
            return v;
        }
        double term(){
            double v=power(); ws();
            while(true){
                if(match('*')) v*=power();
                else if(match('/')) v/=power();
                else if(match('%')){ long long a=(long long)v, b=(long long)power(); v=(double)(a%b); }
                else return v;
                ws();
            }
        }
        double addsub(){
            double v=term(); ws();
            while(true){
                if(match('+')) v+=term();
                else if(match('-')) v-=term();
                else if(i+1<s.size() && s[i]=='/' && s[i+1]=='/'){ i+=2; long long a=(long long)v, b=(long long)term(); v=(double)(a/b); }
                else return v;
                ws();
            }
        }
    };
    static bool safe_eval(const string& e, double& out){
        try{
            Parser p{e,0};
            out = p.expr();
            p.ws();
            if(p.i != p.s.size()) throw runtime_error("trailing characters");
            return true;
        }catch(const exception& ex){
            cerr << "Error: " << ex.what() << "\n";
            return false;
        }
    }

    // -------- Features --------
    static void mdir(){
        string d = getStr("Directory name please: ");
    #if __has_include(<filesystem>)
        error_code ec;
        fs::create_directories(d, ec);
        if(ec) cerr << "[ERROR] mkdir: " << ec.message() << "\n";
    #else
      #if OS_WIN
        run_system(string("mkdir \"")+d+"\"");
      #else
        run_system(string("mkdir -p \"")+d+"\"");
      #endif
    #endif
        char cwd[1024]; if(getcwd(cwd,sizeof(cwd))) cout << "OK, have made a directory called: '"<<d<<"'\nPATH: "<<cwd<<"\n";
    }
    static string read_file_contents(const string& filename){
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "Error opening file!" << endl;
            return "";
        }
        stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
    static void write_to_file(const string& filename, const string& data){
        ofstream file(filename);
        if (!file.is_open()) {
            cerr << "Error opening file!" << endl;
            return;
        }
        file << data;
    }
    static void append_to_file(const string& filename, const string& data){
        ofstream file(filename, ios::app);
        if (!file.is_open()) {
            cerr << "Error opening file!" << endl;
            return;
        }
        file << data;
    }
    static string search_file(const string& filename, const string& term){
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "Error opening file!" << endl;
            return "";
        }
        string line;
        string result;
        while (getline(file, line)) {
            if (line.find(term) != string::npos) {
                result += line + "\n";
            }
        }
        return result;
    }
    static void read_file(){
        string f = getStr("Enter file name to read: ");
        string s = read_file_contents(f);
        if (s.empty()) cerr << "Error: file doesn't exist or can't be read.\n";
        else cout << s << endl;
    }
    static void write_file(){
        string f = getStr("Enter file name to write: ");
        string data = getStr("Enter text to write: ");
        write_to_file(f, data);
        cout << "[SUCCESS] Written to file." << endl;
    }
    static void append_file(){
        string f = getStr("Enter file name to append to: ");
        string data = getStr("Enter text to append: ");
        append_to_file(f, data);
        cout << "[SUCCESS] Appended text to file." << endl;
    }
    static void sfile(){
        string f = getStr("Enter file name to search: ");
        string term = getStr("Enter search term: ");
        string result = search_file(f, term);
        if (result.empty()) cout << "No results found.\n";
        else cout << result << endl;
    }
    static void xor_encrypt_file(const string& filename, const string& key){
        /* DO NOT USE THIS FOR ANYTHING THAT NEEDS TO HAVE GOOD SECURITY *
            It is a form of encryption only used in a pinch if you need it... Use RSA OR AES(they have issues too but far are better than XOR)
        */
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            cerr << "Error opening file!" << endl;
            return;
        }
        ofstream outfile("encrypted_" + filename, ios::binary);
        char ch;
        size_t i = 0;
        while (file.get(ch)) {
            ch ^= key[i % key.size()];
            outfile.put(ch);
            ++i;
        }
        cout << "[SUCCESS] File encrypted with XOR." << endl;
    }
    static void xor_encrypt(){
        string f = getStr("Enter file name to encrypt: ");
        string key = getStr("Enter encryption key: "); 
        xor_encrypt_file(f, key); // Very weak but may help in a pinch. 
    }
    static void netstat_log(){
        string s = run_capture("netstat -an");
        if(s.empty()) cerr << "No active connections." << endl;
        else cout << s << endl;
    }
    static void pchk(){
        string host = getStr("Enter hostname or IP to ping: ");
        string s = run_capture("ping -c 4 " + host);
        if(s.empty()) cerr << "No response from host." << endl;
        else cout << s << endl;
    }
    static void cpuinfo(){
        ofstream mycpuinfo;
        mycpuinfo.open("cpuinfo_output.txt");
        string lscpuinfo = run_capture("lscpu"); //use the run capture function to grab that info from "lscpu" and store it as a string.
        string meminfo = run_capture("free -h"); //Same with "free -h".
        string uptime = run_capture("uptime"); //same with "uptime"
        string s = run_capture("uptime"); //         
        if (s.empty()) cerr << "Could not get uptime information." << endl; 
        mycpuinfo << lscpuinfo << "\n"; //put that into the file
        mycpuinfo << meminfo << "\n"; //same
        mycpuinfo << uptime << "\n"; //same again.
        mycpuinfo << s << "\n"; //same again, again.
        mycpuinfo.close(); //Simples
    }
    static void uptime(){
        string s = run_capture("uptime");
        if (s.empty()) cerr << "Could not get uptime information." << endl;
        else cout << s << endl;
    };
    static void local_info(){
        string s = run_capture("whoami");
        if (s.empty()) cerr << "Could not retrieve user information." << endl;
        else cout << "User: " << s;
    };
    static void file_hash(){
        string filename = getStr("Enter filename to hash: ");
        string s = run_capture("sha256sum " + filename);
        if (s.empty()) cerr << "Error calculating file hash." << endl;
        else cout << "SHA256 Hash: " << s << endl;
    };
};
// Main function to display menu and handle commands
int main() {
    while(true){
        cout << "\n----- Menu -----\n";
        cout << "1. Safe Calculator\n";
        cout << "2. Make Directory\n";
        cout << "3. File Operations (Read/Write/Append/Search)\n";
        cout << "4. XOR Encrypt File\n";
        cout << "5. Network Status\n";
        cout << "6. Ping Host\n";
        cout << "7. CPU Information\n";
        cout << "8. File Hash\n";
        cout << "9. Exit\n";
        int choice = Tool::getInt("Select an option: ");
        switch(choice){
            case 1: {
                string expression = Tool::getStr("Enter an expression to evaluate: ");
                double result;
                if (Tool::safe_eval(expression, result)) {
                    cout << "Result: " << result << endl;
                }
                break;
            }
            case 2:
                Tool::mdir();
                break;
            case 3: {
                int op = Tool::getInt("1. Read file\n2. Write file\n3. Append file\n4. Search file\nSelect option: ");
                switch(op) {
                    case 1: Tool::read_file(); break;
                    case 2: Tool::write_file(); break;
                    case 3: Tool::append_file(); break;
                    case 4: Tool::sfile(); break;
                    default: break;
                }
                break;
            }
            case 4:
                Tool::xor_encrypt();
                break;
            case 5:
                Tool::netstat_log();
                break;
            case 6:
                Tool::pchk();
                break;
            case 7:
                Tool::cpuinfo();
                break;
            case 8:
                Tool::file_hash();
                break;
            case 9:
                return 0; // Just exits
            default:
                cout << "Invalid option!\n";
        };
    };
    return 0;
};
