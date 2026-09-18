#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>
#include <array>
#include <stdexcept>
#include <exception>
#include <system_error>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <regex>
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
    static string str(const string& prompt) {
        cout << prompt;
        string input;
        if (!getline(cin, input)) {
            if (cin.eof()) throw runtime_error("Input stream closed");
            if (cin.fail()) {
                cin.clear();
                throw runtime_error("Input stream failure");
            }
            throw runtime_error("Unable to read input");
        }
        return input;
    }
    static int integer(const string& prompt) {
        try {
            return stoi(str(prompt));
        } catch (const invalid_argument& e) {
            cerr << "Invalid argument: " << e.what() << endl;
            return 0;
        } catch (const out_of_range& e) {
            cerr << "Out of range: " << e.what() << endl;
            return 0;
        } catch (const exception& e) {
            cerr << "Input error: " << e.what() << endl;
            return 0;
        } catch (...) {
            cerr << "An unknown input error occurred." << endl;
            return 0;
        }
    }
    static bool safe(const string& str) {
        return all_of(str.begin(), str.end(), [](char c) {
            return isalnum((unsigned char)c) || c == '/' || c == '_' || c == '.' || c == '-' || c == ':';
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
        try {
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
            if (!fp) {
                cerr << "[ERROR] Command execution failed.\n";
                return "";
            }
            while (fgets(buf.data(), buf.size(), fp)) out += buf.data();
#if OS_WIN
            _pclose(fp);
#else
            pclose(fp);
#endif
            return out;
        } catch (const exception& e) {
            cerr << "[ERROR] Command exception: " << e.what() << "\n";
            return "";
        } catch (...) {
            cerr << "[ERROR] Unknown command exception.\n";
            return "";
        }
    }
    static void run(const vector<string>& args) {
        capture(args);
    }
};
class Calculator {
    struct Parser {
        string s;
        size_t i{0};
        void ws() {
            while (i < s.size() && isspace((unsigned char)s[i])) ++i;
        }
        bool match(char c) {
            ws();
            if (i < s.size() && s[i] == c) {
                ++i;
                return true;
            }
            return false;
        }
        double number() {
            ws();
            size_t j = i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
            while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.')) ++i;
            if (j == i) throw runtime_error("num");
            return stod(s.substr(j, i - j));
        }
        double factor() {
            if (match('+')) return factor();
            if (match('-')) return -factor();
            if (match('(')) {
                double v = expr();
                if (!match(')')) throw runtime_error(")");
                return v;
            }
            return number();
        }
        double power() {
            double v = factor();
            if (match('^')) v = pow(v, power());
            return v;
        }
        double term() {
            double v = power();
            while (true) {
                if (match('*')) v *= power();
                else if (match('/')) v /= power();
                else return v;
            }
        }
        double expr() {
            double v = term();
            while (true) {
                if (match('+')) v += term();
                else if (match('-')) v -= term();
                else return v;
            }
        }
    };
public:
    static bool eval(const string& expr, double& out) {
        try {
            Parser p{expr, 0};
            out = p.expr();
            p.ws();
            return p.i == p.s.size();
        } catch (const exception&) {
            return false;
        } catch (...) {
            return false;
        }
    }
};
class FileOps {
public:
    static bool openFile(ifstream& f, const string& filename) {
        try {
            f.open(filename);
            if (!f) {
                cerr << "[ERROR] Open failed for " << filename << "\n";
                return false;
            }
            return true;
        } catch (const exception& e) {
            cerr << "[ERROR] File open exception: " << e.what() << "\n";
            return false;
        } catch (...) {
            cerr << "[ERROR] Unknown file open exception.\n";
            return false;
        }
    }
    static bool openFile(ofstream& f, const string& filename, ios::openmode mode = ios::trunc) {
        try {
            f.open(filename, mode);
            if (!f) {
                cerr << "[ERROR] Write failed for " << filename << "\n";
                return false;
            }
            return true;
        } catch (const exception& e) {
            cerr << "[ERROR] File write exception: " << e.what() << "\n";
            return false;
        } catch (...) {
            cerr << "[ERROR] Unknown file write exception.\n";
            return false;
        }
    }
    static void mkdir() {
        string dir_name = Input::str("Directory name: ");
        if (fs::exists(dir_name)) {
            cout << "[INFO] Directory already exists.\n";
        } else {
            fs::create_directories(dir_name);
            cout << "[INFO] Directory created.\n";
        }
    }
    static void read() {
        string file = Input::str("File: ");
        if (!fs::exists(file)) {
            cerr << "[ERROR] File does not exist.\n";
            return;
        }
        ifstream f;
        if (!openFile(f, file)) return;
        cout << f.rdbuf();
        if (f.bad()) throw runtime_error("File read failure");
    }
    static void write(bool append = false) {
        string file = Input::str("File: ");
        string text = Input::str("Text: ");
        ofstream out;
        if (!openFile(out, file, append ? ios::app : ios::trunc)) return;
        out << text;
        if (!out) throw runtime_error("File write failure");
    }
    static void search() {
        string file = Input::str("File: ");
        if (!fs::exists(file)) {
            cerr << "[ERROR] File does not exist.\n";
            return;
        }
        ifstream f;
        if (!openFile(f, file)) return;
        string term = Input::str("Term: "), line;
        while (getline(f, line)) {
            if (line.find(term) != string::npos)
                cout << line << "\n";
        }
        if (f.bad()) throw runtime_error("File search read failure");
    }
    static void xor_encrypt() {
        string file = Input::str("File: ");
        if (!fs::exists(file)) {
            cerr << "[ERROR] File does not exist.\n";
            return;
        }
        string key = Input::str("Key: ");
        if (key.empty()) {
            cerr << "[ERROR] Empty key\n";
            return;
        }
        ifstream in(file, ios::binary);
        ofstream out("encrypted_" + file, ios::binary);
        if (!in || !out) {
            cerr << "[ERROR] File error\n";
            return;
        }
        char c;
        size_t i = 0;
        while (in.get(c)) {
            c ^= key[i++ % key.size()];
            out.put(c);
        }
        if (in.bad() || !out) throw runtime_error("XOR file operation failure");
    }
};
class SystemOps {
public:
    static void netstat() {
        cout << Command::capture({"netstat", "-an"});
    }
    static void ping() {
        string host = Input::str("Host: ");
        if (!Input::isValidHost(host)) {
            cerr << "[ERROR] Invalid host\n";
            return;
        }
        vector<string> cmd = {"ping", host};
        if (OS_WIN) {
            cmd.insert(cmd.begin() + 1, "-n");
            cmd.insert(cmd.begin() + 2, "4");
        } else {
            cmd.insert(cmd.begin() + 1, "-c");
            cmd.insert(cmd.begin() + 2, "4");
        }
        cout << Command::capture(cmd);
    }
    static void cpu() {
#if OS_WIN
        cout << Command::capture({"wmic", "cpu", "get", "name"});
#else
        cout << Command::capture({"lscpu"});
#endif
    }
    static void hash() {
        string file = Input::str("File: ");
#if OS_WIN
        cout << Command::capture({"certutil", "-hashfile", file, "SHA256"});
#else
        cout << Command::capture({"sha256sum", file});
#endif
    }
    static void compress() {
        Command::run({"tar", "-czf", "out.tar.gz", Input::str("Target: ")});
    }
    static void extract() {
        Command::run({"tar", "-xzf", Input::str("Archive: ")});
    }
    static void backup() {
#if OS_WIN
        Command::run({"xcopy", Input::str("Src: "), Input::str("Dst: "), "/E", "/I", "/Y"});
#else
        Command::run({"rsync", "-a", Input::str("Src: ") + "/", Input::str("Dst: ") + "/"});
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
        Command::run({"cmd", "/c", "del", "/q", "/f", "/s", "%TEMP%\\*"});
#else
        Command::run({"bleachbit"});
#endif
    }
    static void meminfo() {
#if OS_WIN
        cout << Command::capture({"wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize"});
#else
        cout << Command::capture({"free", "-h"});
#endif
    }
    static void processes() {
#if OS_WIN
        cout << Command::capture({"tasklist"});
#else
        cout << Command::capture({"ps", "aux"});
#endif
    }
    static void killproc() {
        string pid = Input::str("PID: ");
        if (!Input::safe(pid)) {
            cerr << "[ERROR] Invalid PID\n";
            return;
        }
#if OS_WIN
        Command::run({"taskkill", "/PID", pid, "/F"});
#else
        Command::run({"kill", "-9", pid});
#endif
    }
};
class DirectoryMap {
public:
    static void run() {
        ofstream f("directory_map.txt");
        if (!f) {
            cerr << "[ERROR] Failed to create directory map file\n";
            return;
        }
        walk(fs::current_path(), f, 0);
        if (!f) throw runtime_error("Failed while writing directory map");
        cout << "[INFO] Directory map saved\n";
    }
private:
    static void walk(const fs::path& p, ofstream& f, int depth) {
        f << string(depth * 2, ' ') << p.filename().string() << "/\n";
        if (!f) throw runtime_error("Directory map write failure");
        for (auto& entry : fs::directory_iterator(p, fs::directory_options::skip_permission_denied)) {
            if (entry.is_directory())
                walk(entry.path(), f, depth + 1);
            else
                f << string(depth * 2 + 2, ' ') << entry.path().filename().string() << "\n";
            if (!f) throw runtime_error("Directory map write failure");
        }
    }
};
static void printMenu() {
    cout << "\n========================================\n";
    cout << "           Utility Console\n";
    cout << "========================================\n";
    cout << "1)  Calculator       [calc]\n";
    cout << "2)  Make dir         [mkdir]\n";
    cout << "3)  File ops         [file]\n";
    cout << "4)  XOR encrypt      [xor]\n";
    cout << "5)  Netstat          [netstat]\n";
    cout << "6)  Ping             [ping]\n";
    cout << "7)  CPU              [cpu]\n";
    cout << "8)  Hash             [hash]\n";
    cout << "9)  Compress         [compress]\n";
    cout << "10) Extract          [extract]\n";
    cout << "11) Backup           [backup]\n";
    cout << "12) Large files      [largefiles]\n";
    cout << "13) Cleanup          [cleanup]\n";
    cout << "14) Memory           [memory]\n";
    cout << "15) Processes        [processes]\n";
    cout << "16) Kill process     [kill]\n";
    cout << "17) dirmap           [dirmap]\n";
    cout << "18) Help             [help]\n";
    cout << "0)  Exit             [exit/quit]\n";
    cout << "========================================\n";
}
static void helpmenu() {
    printMenu();
    cout << "\nCommands can be entered by number or name.\n";
    cout << "Examples:\n";
    cout << "  calc       - Open calculator\n";
    cout << "  mkdir      - Create a directory\n";
    cout << "  read       - Read a file\n";
    cout << "  write      - Write to a file\n";
    cout << "  append     - Append to a file\n";
    cout << "  search     - Search a file\n";
    cout << "  xor        - XOR encrypt a file\n";
    cout << "  ping       - Ping a host\n";
    cout << "  hash       - Calculate a SHA256 file hash\n";
    cout << "  help       - Show this help\n";
    cout << "  exit       - Exit the console\n";
}
static int commandChoice(const string& command) {
    if (command == "1" || command == "calc" || command == "calculator") return 1;
    if (command == "2" || command == "mkdir" || command == "makedir") return 2;
    if (command == "3" || command == "file" || command == "fileops") return 3;
    if (command == "4" || command == "xor" || command == "encrypt") return 4;
    if (command == "5" || command == "netstat") return 5;
    if (command == "6" || command == "ping") return 6;
    if (command == "7" || command == "cpu") return 7;
    if (command == "8" || command == "hash") return 8;
    if (command == "9" || command == "compress") return 9;
    if (command == "10" || command == "extract") return 10;
    if (command == "11" || command == "backup") return 11;
    if (command == "12" || command == "largefiles" || command == "large") return 12;
    if (command == "13" || command == "cleanup") return 13;
    if (command == "14" || command == "memory" || command == "meminfo") return 14;
    if (command == "15" || command == "processes" || command == "ps") return 15;
    if (command == "16" || command == "kill" || command == "killproc") return 16;
    if (command == "17" || command == "dirmap" || command == "directorymap") return 17;
    if (command == "18" || command == "help" || command == "h" || command == "?") return 18;
    if (command == "0" || command == "exit" || command == "quit" || command == "q") return 0;
    return -1;
}
int main() {
    try {
        printMenu();
        string command;
        do {
            try {
                cout << "\nconsole> ";
                if (!getline(cin, command)) {
                    if (cin.eof()) {
                        cout << "\n[INFO] Input stream closed. Exiting.\n";
                        return 0;
                    }
                    cin.clear();
                    cerr << "[ERROR] Failed to read console input.\n";
                    continue;
                }
                if (command.empty()) continue;
                transform(command.begin(), command.end(), command.begin(), [](unsigned char c) {
                    return static_cast<char>(tolower(c));
                });
                int choice = commandChoice(command);
                if (choice < 0 || choice > 18) {
                    cerr << "[ERROR] Unknown command. Type 'help' for available commands.\n";
                    continue;
                }
                switch (choice) {
                    case 1: {
                        double result = 0.0;
                        if (Calculator::eval(Input::str("Expr: "), result)) {
                            cout << result << "\n";
                        }
                    } break;
                    case 2: FileOps::mkdir(); break;
                    case 3: {
                        string option;
                        cout << "\nFile Operations:\n";
                        cout << "1) Read\n";
                        cout << "2) Write\n";
                        cout << "3) Append\n";
                        cout << "4) Search\n";
                        cout << "Command: ";
                        if (!getline(cin, option)) {
                            if (cin.eof()) return 0;
                            cin.clear();
                            cerr << "[ERROR] Failed to read file operation.\n";
                            break;
                        }
                        transform(option.begin(), option.end(), option.begin(), [](unsigned char c) {
                            return static_cast<char>(tolower(c));
                        });
                        if (option == "1" || option == "read") FileOps::read();
                        else if (option == "2" || option == "write") FileOps::write(false);
                        else if (option == "3" || option == "append") FileOps::write(true);
                        else if (option == "4" || option == "search") FileOps::search();
                        else cerr << "[ERROR] Invalid file operation.\n";
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
                    case 0:
                        cout << "Not an option: exiting!\n";
                        return 0;
                }
            } catch (const fs::filesystem_error& e) {
                cerr << "[FILESYSTEM ERROR] " << e.what() << "\n";
                if (!e.path1().empty())
                    cerr << "[PATH] " << e.path1().string() << "\n";
                if (!e.path2().empty())
                    cerr << "[PATH] " << e.path2().string() << "\n";
                if (e.code())
                    cerr << "[ERROR CODE] " << e.code().value() << ": " << e.code().message() << "\n";
                cerr << "[INFO] Returning to console.\n";
            } catch (const system_error& e) {
                cerr << "[SYSTEM ERROR] " << e.what() << "\n";
                if (e.code())
                    cerr << "[ERROR CODE] " << e.code().value() << ": " << e.code().message() << "\n";
                cerr << "[INFO] Returning to console.\n";
            } catch (const bad_alloc& e) {
                cerr << "[MEMORY ERROR] " << e.what() << "\n";
                cerr << "[INFO] Returning to console.\n";
            } catch (const exception& e) {
                cerr << "[ERROR] " << e.what() << "\n";
                cerr << "[INFO] Returning to console.\n";
            } catch (...) {
                cerr << "[ERROR] Unknown exception caught.\n";
                cerr << "[INFO] Returning to console.\n";
            }
        } while (command != "0" && command != "exit" && command != "quit" && command != "q");
        return 0;
    } catch (const fs::filesystem_error& e) {
        cerr << "[FATAL FILESYSTEM ERROR] " << e.what() << "\n";
        return 1;
    } catch (const system_error& e) {
        cerr << "[FATAL SYSTEM ERROR] " << e.what() << "\n";
        return 1;
    } catch (const bad_alloc& e) {
        cerr << "[FATAL MEMORY ERROR] " << e.what() << "\n";
        return 1;
    } catch (const exception& e) {
        cerr << "[FATAL ERROR] " << e.what() << "\n";
        return 1;
    } catch (...) {
        cerr << "[FATAL ERROR] Unknown exception.\n";
        return 1;
    }
}
//g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic charli_1.1.cpp -o charli
