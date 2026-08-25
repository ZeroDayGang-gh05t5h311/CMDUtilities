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
#include <aclapi.h>
#else
#include <dirent.h>
#include <sys/statvfs.h>
#include <limits.h>
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#endif
#include <sys/inotify.h>
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif


#ifdef _WIN32
#define LOG_FILE "filedaemon.log"
#else
#define LOG_FILE "/var/log/filedaemon.log"
#endif


#define MAX_LOG_SIZE (1024 * 1024 * 5)


/*
    Permission defaults:

    Files:
        0644
        owner read/write
        group read
        others read

    Directories:
        0755
        owner read/write/execute
        group read/execute
        others read/execute
*/
#define FILE_PERMISSION_MODE 0644
#define DIRECTORY_PERMISSION_MODE 0755
int recursive = 0;
int run_flag = 0;
int verbose = 0;
char custom_path[PATH_MAX] = {0};
/*
    Get timestamp for logs
*/
void get_timestamp(char *buf, size_t size)
{
    time_t now;
    struct tm *t;
    now = time(NULL);
    t = localtime(&now);
    if (!t)
    {
        snprintf(buf,size,"unknown-time");
        return;
    }
    strftime(buf,size,"%Y-%m-%d %H:%M:%S",t);
}
/*
    Check free disk space before writing logs
*/
int check_disk_space()
{
#ifdef _WIN32
    ULARGE_INTEGER freeBytes;
    if(GetDiskFreeSpaceEx(
        NULL,
        &freeBytes,
        NULL,
        NULL))
    {
        return freeBytes.QuadPart > (1024 * 1024);
    }
    return 1;
#else
    struct statvfs vfs;
    if(statvfs(".",&vfs)==0)
    {
        return vfs.f_bavail > 0;
    }
    return 1;
#endif
}
/*
    Rotate log file when too large
*/
void rotate_log_if_needed()
{
    struct stat st;
    if(stat(LOG_FILE,&st)==0)
    {
        if(st.st_size > MAX_LOG_SIZE)
        {
#ifdef _WIN32
            MoveFileEx(
                LOG_FILE,
                "filedaemon.log.old",
                MOVEFILE_REPLACE_EXISTING);
#else
            rename(
                LOG_FILE,
                "/var/log/filedaemon.log.old");
#endif
        }

    }
}
/*
    Safe logging function
*/
void log_event(const char *msg)
{
    if(!verbose)
        return;
    if(!msg)
        return;
    if(!check_disk_space())
    {
        verbose = 0;

        fprintf(stderr,
        "Disk full, stopping logs\n");

        return;
    }
    rotate_log_if_needed();
    FILE *f = fopen(LOG_FILE,"a");
    if(!f)
    {
        return;
    }
    char timebuf[64];
    get_timestamp(
        timebuf,
        sizeof(timebuf));
    fprintf(
        f,
        "[%s] %s\n",
        timebuf,
        msg);
    fclose(f);
}
/*
    SAFETY:
    Prevent recursive operations on dangerous system locations.

    This does not replace proper permissions;
    it is an extra protection against accidental misuse.
*/
int unsafe_recursive_path(const char *path)
{
#ifdef _WIN32
    if(!path)
        return 1;
    if(strlen(path)<3)
        return 1;
    return 0;
#else
    const char *blocked[] =
    {
        "/",
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/lib",
        "/lib64",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        NULL
    };
    if(!path || strlen(path)==0)
        return 1;
    for(int i=0; blocked[i]; i++)
    {
        if(strcmp(path,blocked[i])==0)
        {
            return 1;
        }
    }
    return 0;
#endif
}
/*
    SAFETY:
    Validate paths before modifying permissions.
*/
int validate_path(const char *path)
{
    if(!path)
        return 0;
    if(strlen(path)>=PATH_MAX)
        return 0;
#ifndef _WIN32
    struct stat st;
    /*
        lstat prevents following symbolic links
    */
    if(lstat(path,&st)!=0)
    {
        return 0;
    }
    if(S_ISLNK(st.st_mode))
    {
        return 0;
    }
#endif
    return 1;
}
void apply_permissions(const char *path,const char *sys)
{
    char msg[512];
    struct stat st;
    if(!path)
        return;
    if(!validate_path(path))
    {
        snprintf(msg,sizeof(msg),"Rejected unsafe path: %s",path);
        log_event(msg);
        return;
    }
#ifndef _WIN32
    if(strcmp(sys,"Linux")==0||strcmp(sys,"macOS")==0)
    {
        mode_t mode;
        if(lstat(path,&st)==-1)
        {
            snprintf(msg,sizeof(msg),"lstat failed: %s",strerror(errno));
            log_event(msg);
            return;
        }
        if(S_ISLNK(st.st_mode))
        {
            snprintf(msg,sizeof(msg),"Skipped symbolic link: %s",path);
            log_event(msg);
            return;
        }
        if(S_ISDIR(st.st_mode))
            mode=DIRECTORY_PERMISSION_MODE;
        else
            mode=FILE_PERMISSION_MODE;
        if(chmod(path,mode)==-1)
        {
            snprintf(msg,sizeof(msg),"chmod failed for %s: %s",path,strerror(errno));
            log_event(msg);
            return;
        }
        snprintf(msg,sizeof(msg),"%s permission set: %s",sys,path);
        log_event(msg);
    }
#endif
#ifdef _WIN32
    if(strcmp(sys,"Windows")==0)
    {
        EXPLICIT_ACCESS ea;
        PACL pNewAcl=NULL;
        PSID pSid=NULL;
        char *user=getenv("USERNAME");
        if(!user)
            return;
        if(!ConvertStringSidToSid(user,&pSid))
        {
            log_event("Failed to convert Windows user SID");
            return;
        }
        ZeroMemory(&ea,sizeof(EXPLICIT_ACCESS));
        ea.grfAccessPermissions=GENERIC_READ;
        ea.grfAccessMode=GRANT_ACCESS;
        ea.grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm=TRUSTEE_IS_SID;
        ea.Trustee.ptstrName=(LPTSTR)pSid;
        if(SetEntriesInAcl(1,&ea,NULL,&pNewAcl)==ERROR_SUCCESS)
        {
            SetNamedSecurityInfo((LPSTR)path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,pNewAcl,NULL);
        }
        if(pNewAcl)
            LocalFree(pNewAcl);
        if(pSid)
            LocalFree(pSid);
        snprintf(msg,sizeof(msg),"Windows permission set: %s",path);
        log_event(msg);
    }
#endif
}
#ifndef _WIN32
void apply_recursive_unix(const char *base,const char *sys)
{
    DIR *d;
    struct dirent *e;
    char full[PATH_MAX];
    struct stat st;
    if(!base)
        return;
    if(unsafe_recursive_path(base))
    {
        log_event("Blocked unsafe recursive path");
        return;
    }
    if(!validate_path(base))
    {
        log_event("Invalid recursive base path");
        return;
    }
    d=opendir(base);
    if(!d)
    {
        return;
    }
    while((e=readdir(d)))
    {
        if(strcmp(e->d_name,".")==0||strcmp(e->d_name,"..")==0)
            continue;
        snprintf(full,sizeof(full),"%s/%s",base,e->d_name);
        if(!validate_path(full))
        {
            log_event("Skipping unsafe entry");
            continue;
        }
        apply_permissions(full,sys);
        if(lstat(full,&st)==0&&S_ISDIR(st.st_mode))
        {
            apply_recursive_unix(full,sys);
        }
    }
    closedir(d);
}
#endif
#ifdef _WIN32
void apply_recursive_windows(const char *base)
{
    char search[PATH_MAX];
    WIN32_FIND_DATA fd;
    HANDLE h;
    if(!base)
        return;
    snprintf(search,sizeof(search),"%s\\*",base);
    h=FindFirstFile(search,&fd);
    if(h==INVALID_HANDLE_VALUE)
        return;
    do
    {
        char full[PATH_MAX];
        if(strcmp(fd.cFileName,".")==0||strcmp(fd.cFileName,"..")==0)
            continue;
        snprintf(full,sizeof(full),"%s\\%s",base,fd.cFileName);
        apply_permissions(full,"Windows");
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
        {
            apply_recursive_windows(full);
        }
    }
    while(FindNextFile(h,&fd));
    FindClose(h);
}
#endif
void monitor_and_apply_permissions(const char *folder)
{
#ifdef _WIN32
    HANDLE hDir;
    hDir=FindFirstChangeNotification(folder,TRUE,FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_LAST_WRITE|FILE_NOTIFY_CHANGE_ATTRIBUTES);
    if(hDir==INVALID_HANDLE_VALUE)
    {
        log_event("Windows notification failed");
        return;
    }
    while(1)
    {
        DWORD result=WaitForSingleObject(hDir,INFINITE);
        if(result==WAIT_OBJECT_0)
        {
            log_event("Change detected");
            if(recursive)
                apply_recursive_windows(folder);
            else
                apply_permissions(folder,"Windows");
            if(!FindNextChangeNotification(hDir))
            {
                log_event("Windows notification restart failed");
                break;
            }
        }
    }
    FindCloseChangeNotification(hDir);
#elif __APPLE__
    int kq;
    int fd;
    struct kevent change;
    kq=kqueue();
    if(kq==-1)
    {
        log_event("kqueue failed");
        return;
    }
    fd=open(folder,O_EVTONLY);
    if(fd==-1)
    {
        log_event("Failed opening watch folder");
        close(kq);
        return;
    }
    EV_SET(&change,fd,EVFILT_VNODE,EV_ADD|EV_CLEAR,NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|NOTE_DELETE,0,NULL);
    while(1)
    {
        struct kevent event;
        int nev=kevent(kq,&change,1,&event,1,NULL);
        if(nev>0)
        {
            log_event("Change detected on macOS");
            if(recursive)
                apply_recursive_unix(folder,"macOS");
            else
                apply_permissions(folder,"macOS");
        }
    }
    close(fd);
    close(kq);
#else
    int fd;
    int wd;
    char buffer[4096];
    fd=inotify_init();
    if(fd<0)
    {
        log_event("inotify initialization failed");
        return;
    }
    wd=inotify_add_watch(fd,folder,IN_CREATE|IN_MOVED_TO|IN_ATTRIB);
    if(wd<0)
    {
        log_event("inotify watch failed");
        close(fd);
        return;
    }
    while(1)
    {
        ssize_t len=read(fd,buffer,sizeof(buffer));
        if(len<=0)
            continue;
        char *ptr=buffer;
        while(ptr<buffer+len)
        {
            struct inotify_event *event=(struct inotify_event *)ptr;
            if(event->len>0&&event->name[0]!='\0')
            {
                char full[PATH_MAX];
                snprintf(full,sizeof(full),"%s/%s",folder,event->name);
                log_event("Linux filesystem change detected");
                if(validate_path(full))
                {
                    if(recursive)
                        apply_recursive_unix(folder,"Linux");
                    else
                        apply_permissions(full,"Linux");
                }
                else
                {
                    log_event("Rejected unsafe inotify event");
                }
            }
            ptr+=sizeof(struct inotify_event)+event->len;
        }
    }
    close(fd);
#endif
}
const char *get_default_path()
{
#ifdef _WIN32
    static char path[512];
    char *user=getenv("USERPROFILE");
    if(!user)
        return NULL;
    snprintf(path,sizeof(path),"%s\\Downloads",user);
    return path;
#elif __APPLE__
    static char path[512];
    char *home=getenv("HOME");
    if(!home)
        return NULL;
    snprintf(path,sizeof(path),"%s/Downloads",home);
    return path;
#else
    static char path[512];
    char *home=getenv("HOME");
    if(!home)
        return NULL;
    snprintf(path,sizeof(path),"%s/Downloads",home);
    return path;
#endif
}
void print_help()
{
    printf("Usage:\n");
    printf(" -r            Run\n");
    printf(" -p <path>     Path\n");
    printf(" -v            Verbose\n");
    printf(" -h            Help\n");
    printf(" --recursive   Recursive mode\n");
}
void parse_arguments(int argc,char *argv[])
{
    for(int i=1;i<argc;i++)
    {
        if(strcmp(argv[i],"-r")==0)
        {
            run_flag=1;
        }
        else if(strcmp(argv[i],"-v")==0)
        {
            verbose=1;
        }
        else if(strcmp(argv[i],"-h")==0)
        {
            print_help();
            exit(0);
        }
        else if(strcmp(argv[i],"-p")==0&&i+1<argc)
        {
            strncpy(custom_path,argv[++i],PATH_MAX-1);
            custom_path[PATH_MAX-1]='\0';
        }
        else if(strcmp(argv[i],"--recursive")==0)
        {
            recursive=1;
        }
        else
        {
            printf("Unknown option: %s\n",argv[i]);
            print_help();
            exit(1);
        }
    }
}
int main(int argc,char *argv[])
{
    const char *path;
    parse_arguments(argc,argv);
    if(!run_flag)
    {
        print_help();
        return 0;
    }
    if(strlen(custom_path)>0)
        path=custom_path;
    else
        path=get_default_path();
    if(!path)
    {
        printf("Invalid path\n");
        return 1;
    }
    if(!validate_path(path))
    {
        printf("Unsafe or invalid path\n");
        return 1;
    }
    if(recursive&&unsafe_recursive_path(path))
    {
        printf("Recursive operation blocked for safety\n");
        return 1;
    }
    printf("Monitoring: %s\n",path);
    log_event("Program started");
#ifdef _WIN32
    SERVICE_TABLE_ENTRY ServiceTable[]={
        {"FileDaemon",(LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL,NULL}
    };
    if(!StartServiceCtrlDispatcher(ServiceTable))
    {
        log_event("Failed starting Windows service dispatcher");
        return 1;
    }
#else
    monitor_and_apply_permissions(path);
#endif
    return 0;
}
/*
To properly run as a damon on linux:
This is untested on windows and linux as a damon
sudo nano /etc/systemd/system/filedaemon.service
copy and paste this:
"""
[Unit]
Description=File Permission Daemon
[Service]
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
same but for windows:1
In An admin level windows prompt/powershell
sc create FileDaemon binPath= "C:\path\to\exe"
sc start FileDaemon

Updated service examples:

Linux systemd

[Unit]
Description=File Permission Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/filedaemon -r -p /home/user/Downloads
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target

Install:

sudo nano /etc/systemd/system/filedaemon.service

Then:

sudo systemctl daemon-reload
sudo systemctl enable filedaemon
sudo systemctl start filedaemon

Check:

sudo systemctl status filedaemon

Windows service

Run an Administrator PowerShell:

sc.exe create FileDaemon binPath= "C:\path\to\filedaemon.exe -r -p C:\Users\User\Downloads"
sc.exe start FileDaemon
A safe first test:

mkdir -p ~/permission-test/subfolder
echo "hello" > ~/permission-test/test.txt
echo "nested" > ~/permission-test/subfolder/nested.txt

Run:

./filedaemon -r -v -p ~/permission-test --recursive

Then from another terminal:

touch ~/permission-test/newfile.txt
mkdir ~/permission-test/newdir

Check:

ls -la ~/permission-test
ls -la ~/permission-test/subfolder

You should see:

Files:

-rw-r--r--

Directories:

drwxr-xr-x

A few things I would verify before using it on real folders:

Verbose logging

Make sure the log is actually written. On Linux, because the code uses:

#define LOG_FILE "/var/log/filedaemon.log"

the process needs permission to write there. Running as a normal user may silently fail logging.

Recursive protection

Test that this refuses:

./filedaemon -r -p / --recursive

You should get:

Recursive operation blocked for safety
Symlink protection
*/
