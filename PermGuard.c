#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/inotify.h>
#include <limits.h>
#include <dirent.h>
#include <sys/statvfs.h>
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define LOG_FILE "verbose.log"
#define MAX_LOG_SIZE (1024 * 1024 * 5) // 5MB
// Globals
int permission_mode = S_IRUSR | S_IRGRP | S_IROTH;
int recursive = 0;
int run_flag = 0;
int verbose = 0;
char custom_path[PATH_MAX] = {0};
// ---------- TIMESTAMP ----------
void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", t);
}
// ---------- LOG ROTATION ----------
void rotate_log_if_needed() {
    struct stat st;
    if (stat(LOG_FILE, &st) == 0) {
        if (st.st_size > MAX_LOG_SIZE) {
            rename(LOG_FILE, "verbose.log.old");
        }
    }
}
// ---------- DISK CHECK ----------
int check_disk_space() {
#ifdef _WIN32
    ULARGE_INTEGER freeBytes;
    if (GetDiskFreeSpaceEx(NULL, &freeBytes, NULL, NULL)) {
        return freeBytes.QuadPart > (1024 * 1024);
    }
    return 1;
#else
    struct statvfs vfs;
    if (statvfs(".", &vfs) == 0) {
        return vfs.f_bavail > 0;
    }
    return 1;
#endif
}
// ---------- LOG ----------
void log_event(const char* msg) {
    if (!verbose) return;
    if (!check_disk_space()) {
        verbose = 0;
        fprintf(stderr, "Disk full, stopping logs\n");
        return;
    }
    rotate_log_if_needed();
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    char timebuf[64];
    get_timestamp(timebuf, sizeof(timebuf));
    fprintf(f, "[%s] %s\n", timebuf, msg);
    fclose(f);
}
// ---------- PERMISSIONS ----------
void apply_permissions(const char* path, const char* sys) {
    char msg[512];
    if (!path) return;
#ifndef _WIN32
    if (strcmp(sys, "Linux") == 0) {
        if (chmod(path, permission_mode) == -1) {
            snprintf(msg, sizeof(msg), "chmod failed: %s", strerror(errno));
            log_event(msg);
            return;
        }
        snprintf(msg, sizeof(msg), "Linux permission set: %s", path);
        log_event(msg);
    }
#endif
#ifdef _WIN32
    if (strcmp(sys, "Windows") == 0) {
        char cmd[512];
        char *user = getenv("USERNAME");
        if (!user) return;
        snprintf(cmd, sizeof(cmd),
                 "icacls \"%s\" /grant \"%s:(R)\" >nul 2>&1",
                 path, user);
        system(cmd);
        snprintf(msg, sizeof(msg), "Windows permission set: %s", path);
        log_event(msg);
    }
#endif
}
// ---------- RECURSIVE ----------
#ifndef _WIN32
void apply_recursive_linux(const char *base) {
    DIR *d = opendir(base);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", base, e->d_name);
        apply_permissions(full, "Linux");
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            apply_recursive_linux(full);
        }
    }
    closedir(d);
}
#else
void apply_recursive_windows(const char *base) {
    char search[PATH_MAX];
    snprintf(search, sizeof(search), "%s\\*", base);
    WIN32_FIND_DATA fd;
    HANDLE h = FindFirstFile(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
            continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s\\%s", base, fd.cFileName);
        apply_permissions(full, "Windows");
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            apply_recursive_windows(full);
        }
    } while (FindNextFile(h, &fd));
    FindClose(h);
}
#endif
// ---------- WINDOWS SERVICE ----------
#ifdef _WIN32
SERVICE_STATUS status;
SERVICE_STATUS_HANDLE handle;
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(handle, &status);
    }
}
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    handle = RegisterServiceCtrlHandler("FileDaemon", ServiceCtrlHandler);
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(handle, &status);
    log_event("Windows service started");
}
#endif
// ---------- MONITOR ----------
void monitor_and_apply_permissions(const char* folder) {
#ifdef _WIN32
    HANDLE hDir = FindFirstChangeNotification(
        folder, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hDir == INVALID_HANDLE_VALUE) return;
    while (1) {
        if (WaitForSingleObject(hDir, INFINITE) == WAIT_OBJECT_0) {
            log_event("Change detected");
            if (recursive)
                apply_recursive_windows(folder);
            else
                apply_permissions(folder, "Windows");
            FindNextChangeNotification(hDir);
        }
    }
#else
    int fd = inotify_init();
    if (fd < 0) return;
    int wd = inotify_add_watch(fd, folder,
        IN_CREATE | IN_MOVED_TO);
    if (wd < 0) return;
    char buffer[4096];
    while (1) {
        ssize_t len = read(fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        for (char *ptr = buffer; ptr < buffer + len; ) {
            struct inotify_event *event =
                (struct inotify_event *) ptr;
            if (event->len) {
                char full[PATH_MAX];
                snprintf(full, sizeof(full),
                         "%s/%s", folder, event->name);
                log_event("File created/moved");
                if (recursive)
                    apply_recursive_linux(folder);
                else
                    apply_permissions(full, "Linux");
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
#endif
}
// ---------- DEFAULT PATH ----------
const char* get_default_path() {
#ifdef _WIN32
    static char path[512];
    char *user = getenv("USERPROFILE");
    if (!user) return NULL;
    snprintf(path, sizeof(path), "%s\\Downloads", user);
    return path;
#else
    static char path[512];
    char *home = getenv("HOME");
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/Downloads", home);
    return path;
#endif
}
// ---------- CLI ----------
void print_help() {
    printf("Usage:\n");
    printf(" -r            Run\n");
    printf(" -p <path>     Path\n");
    printf(" -v            Verbose\n");
    printf(" -h            Help\n");
}
void parse_arguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r"))
            run_flag = 1;
        else if (!strcmp(argv[i], "-v"))
            verbose = 1;
        else if (!strcmp(argv[i], "-h")) {
            print_help();
            exit(0);
        }
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            strncpy(custom_path, argv[++i], PATH_MAX - 1);
        else if (!strcmp(argv[i], "--recursive"))
            recursive = 1;
    }
}
// ---------- MAIN ----------
int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);
    if (!run_flag) {
        print_help();
        return 0;
    }
    const char *path =
        strlen(custom_path) ? custom_path : get_default_path();
    if (!path) {
        printf("Invalid path\n");
        return 1;
    }

    printf("Monitoring: %s\n", path);
    log_event("Program started");

#ifdef _WIN32
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {"FileDaemon", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcher(ServiceTable);
#else
    monitor_and_apply_permissions(path);
#endif
    return 0;
}
/*
To properly run as a damon on linux:


sudo nano /etc/systemd/system/filedaemon.service

copy and paste this:
"""
[Unit]
Description=File Permission Daemon

[Service]
ExecStart=/path/to/your/program -r -v
Restart=always

[Install]
WantedBy=multi-user.target
"""
Ctr + o (to save when in nano)
Ctr + x (to exit)

then;

sudo systemctl daemon-reexec
sudo systemctl enable filedaemon
sudo systemctl start filedaemon

same but for windows:
In An admin level windows prompt/powershell
sc create FileDaemon binPath= "C:\path\to\exe"
sc start FileDaemon

*/
