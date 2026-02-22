#include <iostream>   // For input/output operations
#include <fstream>    // For file stream operations
#include <filesystem> // For filesystem manipulation (directories, files)
#include <vector>     // For using vectors (dynamic arrays)
#include <string>     // For handling strings
#include <sstream>    // For string stream operations
#include <cmath>      // For mathematical functions (like pow)
#include <array>      // For using fixed-size arrays
#include <stdexcept>  // For exception handling
#include <cctype>     // For character classification (isdigit, isalnum)
#include <cstdlib>    // For system-related utilities
#include <algorithm> //for algorithm things.
#if defined(_WIN32)
    #include <windows.h> // Windows-specific headers
    #define OS_WIN 1
#else
    #include <unistd.h>   // Unix-specific headers
    #include <pwd.h>      // For accessing user information (Unix)
    #define OS_WIN 0
#endif
namespace fs = std::filesystem;  // Alias for filesystem namespace
using namespace std;              // Use the standard namespace for easier access
// Class to handle user inputs
class Input {
public:
    // Get a string from the user
    static string str(const string& prompt) {
        cout << prompt; 
        string input; 
        getline(cin, input); 
        return input;
    }
    // Get an integer from the user, with exception handling
    static int integer(const string& prompt) {
        try { 
            return stoi(str(prompt)); 
        } catch (...) { 
            return 0; // Return 0 if there's an error
        }
    }
    // Check if a string is safe (alphanumeric or certain symbols)
    static bool safe(const string& str) {
        return all_of(str.begin(), str.end(), [](char c) {
            return isalnum((unsigned char)c) || c == '/' || c == '_' || c == '.' || c == '-' || c == ':';
        });
    }
};
// Class to handle system commands
class Command {
public:
    // Capture the output of a system command
    static string capture(const vector<string>& args) {
        string cmd;
        for (const auto& a : args) {
            if (!Input::safe(a)) throw runtime_error("Unsafe argument");
            cmd += a + " ";  // Build the command string
        }
        array<char, 1024> buf{}; 
        string out;
#if OS_WIN
        FILE* fp = _popen(cmd.c_str(), "r");  // Windows command execution
#else
        FILE* fp = popen(cmd.c_str(), "r");   // Unix command execution
#endif
        if (!fp) return ""; // If file pointer is null, return empty string
        while (fgets(buf.data(), buf.size(), fp)) out += buf.data(); // Read output
#if OS_WIN
        _pclose(fp);  // Close Windows process handle
#else
        pclose(fp);   // Close Unix process handle
#endif
        return out; // Return the captured output
    }
    // Execute a command without capturing the output
    static void run(const vector<string>& args) {
        capture(args); // Just call capture for side-effects
    }
};
// Calculator class for parsing and evaluating mathematical expressions
class Calculator {
    // Inner Parser class for expression parsing
    struct Parser {
        string s;        // Expression string
        size_t i{0};     // Index for current parsing position
        // Skip whitespace characters
        void ws() { 
            while (i < s.size() && isspace((unsigned char)s[i])) ++i; 
        }
        // Match a specific character in the string
        bool match(char c) { 
            ws(); 
            if (i < s.size() && s[i] == c) { ++i; return true; } 
            return false; 
        }
        // Parse a number from the string
        double number() { 
            ws(); 
            size_t j = i; 
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i; // Handle signs
            while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.')) ++i; // Read digits and decimal points
            if (j == i) throw runtime_error("num"); // Throw if no number found
            return stod(s.substr(j, i - j)); // Convert the substring to a double
        }
        // Parse a factor (which could be a number, parenthesized expression, or unary +/−)
        double factor() { 
            if (match('+')) return factor();  // Unary plus
            if (match('-')) return -factor(); // Unary minus
            if (match('(')) { 
                double v = expr(); 
                if (!match(')')) throw runtime_error(")"); // Expect closing parenthesis
                return v;
            }
            return number(); // Otherwise, parse a number
        }
        // Parse an exponentiation
        double power() { 
            double v = factor(); 
            if (match('^')) v = pow(v, power()); // Parse power operation
            return v;
        }
        // Parse terms (multiplication/division)
        double term() { 
            double v = power(); 
            while (true) { 
                if (match('*')) v *= power();  // Multiplication
                else if (match('/')) v /= power(); // Division
                else return v;  // Return the result
            }
        }
        // Parse expressions (addition/subtraction)
        double expr() { 
            double v = term(); 
            while (true) { 
                if (match('+')) v += term();  // Addition
                else if (match('-')) v -= term(); // Subtraction
                else return v; // Return the result
            }
        }
    };

public:
    // Evaluate an expression and store the result in 'out'
    static bool eval(const string& expr, double& out) {
        try { 
            Parser p{ expr, 0 }; 
            out = p.expr(); 
            p.ws(); 
            return p.i == p.s.size(); // If the whole string is parsed, return true
        } catch (...) { 
            return false; // Return false if an error occurred during parsing
        }
    }
};
// File operations class
class FileOps {
public:
    // Open a file for reading
    static bool openFile(ifstream& f, const string& filename) { 
        f.open(filename); 
        if (!f) { 
            cerr << "[ERROR] Open failed for " << filename << "\n"; 
            return false; 
        } 
        return true; 
    }
    // Open a file for writing (with mode specified)
    static bool openFile(ofstream& f, const string& filename, ios::openmode mode = ios::trunc) { 
        f.open(filename, mode); 
        if (!f) { 
            cerr << "[ERROR] Write failed for " << filename << "\n"; 
            return false; 
        } 
        return true; 
    }
    // Create a new directory
    static void mkdir() { 
        fs::create_directories(Input::str("Directory name: ")); 
        cout << "[INFO] Directory created\n"; 
    }
    // Read from a file
    static void read() { 
        ifstream f; 
        string file = Input::str("File: "); 
        if (!openFile(f, file)) return; 
        cout << f.rdbuf(); // Output file contents to console
    }
    // Write to a file
    static void write(bool append = false) { 
        string file = Input::str("File: "); 
        string text = Input::str("Text: "); 
        ofstream out; 
        if (!openFile(out, file, append ? ios::app : ios::trunc)) return; 
        out << text; // Write text to file
    }
    // Search a term in a file
    static void search() { 
        ifstream f; 
        string file = Input::str("File: "); 
        if (!openFile(f, file)) return; 
        string term = Input::str("Term: "), line; 
        while (getline(f, line)) { 
            if (line.find(term) != string::npos) 
                cout << line << "\n"; // Output matching lines
        } 
    }
    // XOR encryption of a file
    static void xor_encrypt() { 
        string file = Input::str("File: "); 
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
            c ^= key[i++ % key.size()]; // XOR encryption
            out.put(c); 
        }
    }
};
// System operations class
class SystemOps {
public:
    // Display network statistics
    static void netstat() { 
        cout << Command::capture({ "netstat", "-an" }); 
    }
    // Ping a host
    static void ping() { 
        string host = Input::str("Host: "); 
        if (!Input::safe(host)) { 
            cerr << "[ERROR]\n"; 
            return; 
        }
        vector<string> cmd = { "ping", host }; 
        if (OS_WIN) { 
            cmd.insert(cmd.begin() + 1, "-n"); 
            cmd.insert(cmd.begin() + 2, "4"); 
        } else { 
            cmd.insert(cmd.begin() + 1, "-c"); 
            cmd.insert(cmd.begin() + 2, "4"); 
        } 
        cout << Command::capture(cmd); 
    }
    // Display CPU information
    static void cpu() { 
        #if OS_WIN 
        cout << Command::capture({ "wmic", "cpu", "get", "name" }); 
        #else 
        cout << Command::capture({ "lscpu" }); 
        #endif 
    }
    // Display file hash
    static void hash() { 
        string file = Input::str("File: "); 
        #if OS_WIN 
        cout << Command::capture({ "certutil", "-hashfile", file, "SHA256" }); 
        #else 
        cout << Command::capture({ "sha256sum", file }); 
        #endif 
    }
    // Compress a directory into a tarball
    static void compress() { 
        Command::run({ "tar", "-czf", "out.tar.gz", Input::str("Target: ") }); 
    }
    // Extract a tarball
    static void extract() { 
        Command::run({ "tar", "-xzf", Input::str("Archive: ") }); 
    }
    // Backup files/directories
    static void backup() { 
        #if OS_WIN 
        Command::run({ "xcopy", Input::str("Src: "), Input::str("Dst: "), "/E", "/I", "/Y" }); 
        #else 
        Command::run({ "rsync", "-a", Input::str("Src: ") + "/", Input::str("Dst: ") + "/" }); 
        #endif 
    }
    // Find large files in a directory
    static void largefiles() { 
        cout << Command::capture({ 
            "find", 
            Input::str("Dir: "), 
            "-type", "f", 
            "-size", "+" + to_string(Input::integer("KB: ")) + "k" 
        }); 
    }
    // Clean up temporary files
    static void cleanup() { 
        #if OS_WIN 
        Command::run({ "cmd", "/c", "del", "/q", "/f", "/s", "%TEMP%\\*" }); 
        #else 
        Command::run({ "rm", "-rf", "/tmp/*" }); 
        #endif 
    }
    // Display memory information
    static void meminfo() { 
        #if OS_WIN 
        cout << Command::capture({ "wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize" }); 
        #else 
        cout << Command::capture({ "free", "-h" }); 
        #endif 
    }
    // List running processes
    static void processes() { 
        #if OS_WIN 
        cout << Command::capture({ "tasklist" }); 
        #else 
        cout << Command::capture({ "ps", "aux" }); 
        #endif 
    }
    // Kill a process by PID
    static void killproc() { 
        string pid = Input::str("PID: "); 
        if (!Input::safe(pid)) { 
            cerr << "[ERROR]\n"; 
            return; 
        }
        #if OS_WIN 
        Command::run({ "taskkill", "/PID", pid, "/F" }); 
        #else 
        Command::run({ "kill", "-9", pid }); 
        #endif 
    }
};
// Directory map generator
class DirectoryMap {
public:
    // Generate a directory map and save it to a file
    static void run() { 
        ofstream f("directory_map.txt"); 
        if (!f) { 
            cerr << "[ERROR]\n"; 
            return; 
        }
        walk(fs::current_path(), f, 0); 
        cout << "[INFO] Directory map saved\n"; 
    }
private:
    // Recursive function to walk the directory tree and output file structure
    static void walk(const fs::path& p, ofstream& f, int depth) { 
        f << string(depth * 2, ' ') << p.filename().string() << "/\n"; 
        for (auto& entry : fs::directory_iterator(p, fs::directory_options::skip_permission_denied)) { 
            if (entry.is_directory()) 
                walk(entry.path(), f, depth + 1); // Recurse into directories
            else 
                f << string(depth * 2 + 2, ' ') << entry.path().filename().string() << "\n"; // List file
        }
    }
};
// Print the main menu options
static void printMenu() { 
    cout << "\n--- MENU ---\n"; 
    cout << "1) Calculator\n2) Make dir\n3) File ops\n4) XOR encrypt\n5) Netstat\n6) Ping\n7) CPU\n8) Hash\n"; 
    cout << "9) Compress\n10) Extract\n11) Backup\n12) Large files\n13) Cleanup\n14) Memory\n15) Processes\n"; 
    cout << "16) Kill process\n17) dirmap\n18) help(this text)\n0 Exit\n"; 
}
// Show the help menu (same as the main menu)
static void helpmenu() { 
    printMenu(); 
}
// Main entry point of the application
int main() { 
    printMenu(); // Show the main menu
    while (true) { 
        switch (Input::integer("Choice: ")) { 
            case 1: { 
                double result; 
                if (Calculator::eval(Input::str("Expr: "), result)) 
                    cout << result << "\n"; 
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
            case 0: cout << "Not an option: exiting!\n"; return 0; 
        } 
    }
}
