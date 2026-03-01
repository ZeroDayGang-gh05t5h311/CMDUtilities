#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>  // Include syslog.h for openlog and related constants
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/inotify.h>
#include <limits.h>
#include <dirent.h>
#endif

// Function prototypes
void print_help();
void daemonize();

// Define default download folder path
#ifdef _WIN32
#define DEFAULT_DOWNLOAD_FOLDER_Win "C:\\Users\\%USERNAME%\\Downloads"  // Windows path
#else
#define DEFAULT_DOWNLOAD_FOLDER_Linux "/home/username/Downloads"  // Linux path (change accordingly)
#endif

// Default permissions
int permission_mode = S_IRUSR | S_IRGRP | S_IROTH;  // Default read-only permissions (Linux)
int recursive = 0;  // Default not to apply recursively

// Log function for logging permissions changes and errors
void log_event(const char* message) {
    FILE *log_file = fopen("file_permission_daemon.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", message);
        fclose(log_file);
    } else {
        fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
    }
}

// Helper function to apply permissions on both Linux and Windows
void apply_permissions(const char* file_path, const char* system_type) {
    char log_message[512];
    if (strcmp(system_type, "Linux") == 0) {
        int result = chmod(file_path, permission_mode);
        if (result == -1) {
            log_event("Error: chmod failed on file (Linux)");
            perror("chmod failed");
            return;
        }
        snprintf(log_message, sizeof(log_message), "Applied permission (Linux) to: %s", file_path);
        log_event(log_message);
    }
    else if (strcmp(system_type, "Windows") == 0) {
        char command[512];
        snprintf(command, sizeof(command), "icacls \"%s\" /grant \"%s:(R)\"", file_path, getenv("USERNAME"));
        int result = system(command);
        if (result == -1) {
            log_event("Error: icacls failed on file (Windows)");
            perror("icacls failed");
            return;
        }
        snprintf(log_message, sizeof(log_message), "Applied read-only permission (Windows) to: %s", file_path);
        log_event(log_message);
    }
}

// Cross-platform file monitoring and permission setting
void monitor_and_apply_permissions(const char* download_folder) {
#ifdef _WIN32
    // Windows-specific file monitoring using FindFirstChangeNotification
    HANDLE hDir = FindFirstChangeNotification(download_folder, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hDir == INVALID_HANDLE_VALUE) {
        log_event("Error: FindFirstChangeNotification failed (Windows)");
        fprintf(stderr, "Error in FindFirstChangeNotification\n");
        return;
    }
    DWORD dwWaitStatus;
    while (1) {
        dwWaitStatus = WaitForSingleObject(hDir, INFINITE);
        if (dwWaitStatus == WAIT_OBJECT_0) {
            // Handle file change, apply permissions
            printf("File added to download directory, applying permissions...\n");
            apply_permissions(download_folder, "Windows");
            FindNextChangeNotification(hDir);
        } else {
            log_event("Error: WaitForSingleObject failed (Windows)");
            fprintf(stderr, "Error in WaitForSingleObject\n");
            break;
        }
    }
    FindCloseChangeNotification(hDir);
#else
    // Linux-specific file monitoring using inotify
    int fd = inotify_init();
    if (fd == -1) {
        log_event("Error: inotify_init failed (Linux)");
        perror("inotify_init failed");
        return;
    }
    int wd = inotify_add_watch(fd, download_folder, IN_CREATE | IN_MOVED_TO);
    if (wd == -1) {
        log_event("Error: inotify_add_watch failed (Linux)");
        perror("inotify_add_watch failed");
        close(fd);
        return;
    }
    char buffer[1024];
    while (1) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length == -1) {
            log_event("Error: read failed (Linux)");
            perror("read failed");
            break;
        }
        for (char *ptr = buffer; ptr < buffer + length; ) {
            struct inotify_event *event = (struct inotify_event *) ptr;
            if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
                char file_path[PATH_MAX];
                snprintf(file_path, sizeof(file_path), "%s/%s", download_folder, event->name);
                apply_permissions(file_path, "Linux");
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
    close(fd);
#endif
}

// Function to get the appropriate download folder path dynamically
const char* get_download_folder_path() {
#ifdef _WIN32
    // Get the Windows download folder dynamically
    char* user_profile = getenv("USERPROFILE");
    if (user_profile == NULL) {
        return NULL;
    }
    static char download_path[512];
    snprintf(download_path, sizeof(download_path), "%s\\Downloads", user_profile);
    return download_path;
#else
    // Get the Linux download folder dynamically
    char* user_home = getenv("HOME");
    if (user_home == NULL) {
        return NULL;
    }
    static char download_path[512];
    snprintf(download_path, sizeof(download_path), "%s/Downloads", user_home);
    return download_path;
#endif
}

// Function to parse command-line arguments
void parse_arguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_help();
            exit(0);
        }
        if (strcmp(argv[i], "--permissions") == 0 && i + 1 < argc) {
            // Parse permissions (e.g., rwx)
            char *perm = argv[++i];
            permission_mode = 0;
            if (strchr(perm, 'r')) permission_mode |= S_IRUSR | S_IRGRP | S_IROTH;
            if (strchr(perm, 'w')) permission_mode |= S_IWUSR | S_IWGRP | S_IWOTH;
            if (strchr(perm, 'x')) permission_mode |= S_IXUSR | S_IXGRP | S_IXOTH;
        }
        else if (strcmp(argv[i], "--recursive") == 0) {
            // Enable recursive permissions
            recursive = 1;
        }
        else if (strcmp(argv[i], "--background") == 0) {
            // Start in background mode
#ifdef __linux__
            daemonize();  // Linux: daemonize process
#endif
        }
    }
}

// Function to print the help menu
void print_help() {
    printf("Usage: file_permission_daemon [options]\n");
    printf("\nOptions:\n");
    printf("  --permissions [rwx]      Set the permissions for files (default: read-only)\n");
    printf("                            r - read, w - write, x - execute (e.g., rwx for read, write, execute)\n");
    printf("  --recursive              Apply permissions recursively to subdirectories.\n");
    printf("  --background             Run the program in the background (daemonize on Linux).\n");
    printf("  --help                   Display this help message and exit.\n");
}

// Linux: Daemonize the process
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        log_event("Error: Fork failed to daemonize");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    if (setsid() < 0) {
        log_event("Error: setsid() failed");
        exit(EXIT_FAILURE);
    }
    if (chdir("/") < 0) {
        log_event("Error: chdir() to / failed");
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    openlog("file_permission_daemon", LOG_PID | LOG_NOWAIT, LOG_USER);
}

#ifdef _WIN32
void run_in_background() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcess(NULL, "file_permission_daemon.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        log_event("Error: CreateProcess failed to start background process");
    }
}
#endif
int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);  // Parse the arguments
    const char *download_folder = (argc > 1) ? argv[1] : get_download_folder_path();
    if (download_folder == NULL) {
        fprintf(stderr, "Error: Unable to determine the download folder path\n");
        return 1;
    }
    log_event("Daemon started");
    printf("Monitoring the download folder: %s\n", download_folder);
#ifdef _WIN32
    if (recursive) {
        // Handle recursive permission application on Windows (optional, just for illustration)
        // Implement recursive permission logic if needed for Windows
    }
    run_in_background();  // Windows background process
#endif
    monitor_and_apply_permissions(download_folder);
    return 0;
}
