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
        if(!fp) {
            cerr << "[ERROR]: Failed to run command: " << cmd << endl;
            return data;
        }
        char buf[1024];
        while(fgets(buf,sizeof(buf),fp)) data += buf;
    #if OS_WIN
        _pclose(fp);
    #else
        pclose(fp);
    #endif
        return data;
    }
    static int run_system(const string& cmd) {
        int rc = system(cmd.c_str());
        if(rc != 0) {
            cerr << "[ERROR]: Command failed: " << cmd << " (rc=" << rc << ")\n";
        }
        return rc;
    }
    static int getInt(const string& prompt) {
        cout << prompt;
        string s; 
        getline(cin, s);
        try { 
            return stoi(s); 
        } catch(const exception& e) {
            cerr << "[ERROR]: Invalid input: " << s << " (Error: " << e.what() << ")" << endl;
            return 0; 
        }
    }
    static string getStr(const string& prompt){
        cout << prompt;
        string s; 
        getline(cin, s);
        return s;
    }
    /* -------- SafeCalc -------- */
    struct Parser {
        string s; size_t i{0};
        void ws(){ 
            while(i<s.size() && isspace((unsigned char)s[i])) ++i; 
        }
        bool match(char c){ 
            ws(); 
            if(i<s.size() && s[i]==c){ 
                ++i; 
                return true; 
            } 
            return false; 
        }
        double number(){
            ws();
            size_t j=i;
            if(i<s.size() && (s[i]=='+'||s[i]=='-')) ++i;
            while(i<s.size() && (isdigit((unsigned char)s[i]) || s[i]=='.')) ++i;
            if(j==i) throw runtime_error("expected number"); 
            return stod(s.substr(j,i-j));
        }
        double expr() { 
            return addsub(); 
        }
        double factor()  {
            ws();
            if(match('+')) return factor();
            if(match('-')) return -factor();
            if(match('(')){ 
                double v=expr(); 
                if(!match(')')) throw runtime_error("missing ')'");
                return v; 
            }
            return number();
        }
        double power() {
            double v=factor(); 
            ws();
            while(match('^')){ 
                double r=factor(); 
                v = pow(v,r); 
                ws(); 
            }
            return v;
        }
        double term() {
            double v=power(); 
            ws();
            while(true){
                if(match('*')) v*=power();
                else if(match('/')) v/=power();
                else if(match('%')){
                    long long a=(long long)v, b=(long long)power(); 
                    v=(double)(a%b); 
                }
                else return v;
                ws();
            }
        }
        double addsub() {
            double v=term(); 
            ws();
            while(true){
                if(match('+')) v+=term();
                else if(match('-')) v-=term();
                else if(i+1<s.size() && s[i]=='/' && s[i+1]=='/'){
                    i+=2; 
                    long long a=(long long)v, b=(long long)term(); 
                    v=(double)(a/b); 
                }
                else return v;
                ws();
            }
        }
    };
    static bool safe_eval(const string& e, double& out) {
        try{
            Parser p{e,0};
            out = p.expr();
            p.ws();
            if(p.i != p.s.size()) throw runtime_error("trailing characters");
            return true;
        } catch(const exception& ex){
            cerr << "[ERROR]: Evaluation failed for expression '" << e << "': " << ex.what() << "\n";
            return false;
        }
    }
    // -------- Features --------
    static void mdir() {
        string d = getStr("Directory name please: ");
        error_code ec;
        fs::create_directories(d, ec);
        if(ec)
            cerr << "[ERROR]: mkdir: " << ec.message() << "\n";
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)))
            cout << "[INFO]: Directory '" << d << "' created successfully. Current path: " << cwd << "\n";
        else
            cerr << "[ERROR]: Failed to get current directory path.\n";
    }
    static string read_file_contents(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "[ERROR]: Could not open file: " << filename << endl;
            return "";
        }
        stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
    static void write_to_file(const string& filename, const string& data) {
        ofstream file(filename);
        if (!file.is_open()) {
            cerr << "[ERROR]: Could not open file for writing: " << filename << endl;
            return;
        }
        file << data;
        cout << "[INFO]: Data written to file: " << filename << endl;
    }
    static void append_to_file(const string& filename, const string& data) {
        ofstream file(filename, ios::app);
        if (!file.is_open()) {
            cerr << "[ERROR]: Could not open file for appending: " << filename << endl;
            return;
        }
        file << data;
        cout << "[INFO]: Data appended to file: " << filename << endl;
    }
    static string search_file(const string& filename, const string& term) {
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "[ERROR]: Could not open file for searching: " << filename << endl;
            return "";
        }
        string result, line;
        while (getline(file, line)) {
            if (line.find(term) != string::npos) {
                result += line + "\n";
            }
        }
        return result;
    }
    static void read_file() {
        string f = getStr("Enter file name to read: ");
        string s = read_file_contents(f);
        if (s.empty()) cerr << "[ERROR]: File is empty or cannot be read." << endl;
        else cout << "[INFO]: File contents:\n" << s << endl;
    }
    static void write_file() {
        string f = getStr("Enter file name to write: ");
        string data = getStr("Enter text to write: ");
        write_to_file(f, data);
    }
    static void append_file() {
        string f = getStr("Enter file name to append to: ");
        string data = getStr("Enter text to append: ");
        append_to_file(f, data);
    }
    static void sfile() {
        string f = getStr("Enter file name to search: ");
        string term = getStr("Enter search term: ");
        string result = search_file(f, term);
        if (result.empty()) cout << "[INFO]: No results found.\n";
        else cout << "[INFO]: Search results:\n" << result << endl;
    }
    static void xor_encrypt_file(const string& filename, const string& key){
        if (key.empty()) {
            cerr << "[ERROR]: Key cannot be empty.\n";
            return;
        }
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            cerr << "[ERROR]: Could not open file for encryption: " << filename << endl;
            return;
        }
        ofstream outfile("encrypted_" + filename, ios::binary);
        if (!outfile.is_open()) {
            cerr << "[ERROR]: Could not create output file: encrypted_" << filename << endl;
            return;
        }
        char ch;
        size_t i = 0;
        while (file.get(ch)) {
            ch ^= key[i % key.size()];
            outfile.put(ch);
            ++i;
        }
        cout << "[INFO]: File encrypted successfully: encrypted_" << filename << endl;
    }
    static void xor_encrypt() {
        string f = getStr("Enter file name to encrypt: ");
        string key = getStr("Enter encryption key: ");
        xor_encrypt_file(f, key); 
    }
    static void netstat_log() {
    #if OS_WIN
        string s = run_capture("netstat -an");
    #else
        string s = run_capture("netstat -an");
    #endif
        if(s.empty()) cerr << "[ERROR]: No active connections or failed to fetch data." << endl;
        else cout << "[INFO]: Active network connections:\n" << s << endl;
    }
    static void pchk() {
        string host = getStr("Enter hostname or IP to ping: ");
    #if OS_WIN
        string s = run_capture("ping -n 4 " + host);
    #else
        string s = run_capture("ping -c 4 " + host);
    #endif
        if(s.empty()) cerr << "[ERROR]: No response from host." << endl;
        else cout << "[INFO]: Ping results:\n" << s << endl;
    }
    static void cpuinfo() {
        ofstream mycpuinfo("cpuinfo_output.txt");
    #if OS_WIN
        string cpu = run_capture("wmic cpu get name");
        string mem = run_capture("wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /format:table");
        string up  = run_capture("net statistics workstation");

        mycpuinfo << cpu << "\n" << mem << "\n" << up << "\n";
    #else
        mycpuinfo << run_capture("lscpu") << "\n";
        mycpuinfo << run_capture("free -h") << "\n";
        mycpuinfo << run_capture("uptime") << "\n";
        mycpuinfo << run_capture("netstat -tuln") << "\n";
    #endif
        cout << "[INFO]: CPU information saved to cpuinfo_output.txt" << endl;
    }
    static void file_hash() {
        string filename = getStr("Enter filename to hash: ");
    #if OS_WIN
        string s = run_capture("certutil -hashfile \"" + filename + "\" SHA256");
    #else
        string s = run_capture("sha256sum \"" + filename + "\"");
    #endif
        if (s.empty()) cerr << "[ERROR]: Error calculating file hash." << endl;
        else cout << "[INFO]: File SHA256 Hash: " << s << endl;
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
// -------- Main Menu --------
int main(void) {
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
        cout << "9. Directory mapper\n";
        cout << "10. Exit\n";
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
                    default:
                        cout << "Oh dear, wrong input: exiting!" << endl; 
                        break;
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
                Tool::dirmap();
                break;
            case 10:
                return 0;
            default:
                cout << "Invalid option!\n" << endl;
        }
    }
    return 0;
}
