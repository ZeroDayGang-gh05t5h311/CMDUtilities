#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#endif
// Define default download folder path
#ifdef _WIN32
#define DEFAULT_DOWNLOAD_FOLDER "C:\\Users\\%USERNAME%\\Downloads"  // Windows path
#else
#define DEFAULT_DOWNLOAD_FOLDER "/home/username/Downloads"  // Linux path (change accordingly)
#endif
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
        int result = chmod(file_path, S_IRUSR | S_IRGRP | S_IROTH);
        if (result == -1) {
            log_event("Error: chmod failed on file (Linux)");
            perror("chmod failed");
            return;
        }
        snprintf(log_message, sizeof(log_message), "Applied read-only permission (Linux) to: %s", file_path);
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
int main(int argc, char *argv[]) {
    const char *download_folder = (argc > 1) ? argv[1] : DEFAULT_DOWNLOAD_FOLDER;
    // Log the start of the daemon
    log_event("Daemon started");
    printf("Monitoring the download folder: %s\n", download_folder);
    monitor_and_apply_permissions(download_folder);
    return 0;
}
