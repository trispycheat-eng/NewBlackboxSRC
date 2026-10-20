#include <jni.h>
#include <string>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <errno.h>

#include <android/log.h>
#define LOG_TAG "Trispy10x"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- GLOBALS ---
static int (*orig_system_property_get)(const char* name, char* value) = nullptr;
static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = nullptr;
static FILE* (*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static int (*orig_stat)(const char *pathname, struct stat *statbuf) = nullptr;
static int (*orig_access)(const char *pathname, int mode) = nullptr;
static int (*orig_ptrace)(int request, pid_t pid, void *addr, void *data) = nullptr;

// --- PROPERTY SPOOFER ---
struct FakeProp { const char* name; const char* value; };
static FakeProp fake_props[] = {
    {"ro.product.model", "SM-S928B"}, {"ro.product.brand", "samsung"},
    {"ro.product.manufacturer", "samsung"}, {"ro.hardware", "qcom"},
    {"ro.kernel.qemu", "0"}, {"ro.vbox", "0"}, {"ro.vphonegaga", "0"},
    {"ro.secure", "1"}, {"ro.debuggable", "0"}, {"ro.build.tags", "release-keys"},
    {"ro.build.type", "user"}, {"ro.boot.verifiedbootstate", "green"}
};

int my_system_property_get(const char* name, char* value) {
    if (name != nullptr && value != nullptr) {
        for (size_t i = 0; i < sizeof(fake_props)/sizeof(fake_props[0]); i++) {
            if (strcmp(name, fake_props[i].name) == 0) {
                strcpy(value, fake_props[i].value);
                return strlen(value);
            }
        }
        if (strstr(name, "magisk") || strstr(name, "zygisk") || strstr(name, "vbox") || strstr(name, "qemu")) {
            strcpy(value, "0");
            return 1;
        }
    }
    return orig_system_property_get(name, value);
}

// --- FILE HIDER ---
bool is_suspicious(const char* path) {
    if (path == nullptr) return false;
    if (strstr(path, "com.android.support") || strstr(path, "trispy") || strstr(path, "libjni")) return true;
    if (strstr(path, "magisk") || strstr(path, "zygisk") || strstr(path, "su") || strstr(path, "superuser")) return true;
    if (strstr(path, "lspatch") || strstr(path, "npatch") || strstr(path, "lspd")) return true;
    if (strstr(path, "frida") || strstr(path, "xposed")) return true;
    return false;
}

int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (is_suspicious(pathname)) { errno = ENOENT; return -1; }
    return orig_openat(dirfd, pathname, flags, mode);
}

FILE* my_fopen(const char *pathname, const char *mode) {
    if (is_suspicious(pathname)) { errno = ENOENT; return nullptr; }
    return orig_fopen(pathname, mode);
}

int my_stat(const char *pathname, struct stat *statbuf) {
    if (is_suspicious(pathname)) { errno = ENOENT; return -1; }
    return orig_stat(pathname, statbuf);
}

int my_access(const char *pathname, int mode) {
    if (is_suspicious(pathname)) { errno = ENOENT; return -1; }
    return orig_access(pathname, mode);
}

// --- PTRACE BLOCKER ---
int my_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        errno = EPERM; return -1;
    }
    return orig_ptrace(request, pid, addr, data);
}

// --- INITIALIZER ---
static void* bypass_thread(void*) {
    sleep(2); 
    LOGI("10x Bypass loaded into NPatch/Blackbox environment.");
    // The hooking logic goes here using the engine's hook framework.
    return nullptr;
}

__attribute__((constructor))
void bypass_init() {
    pthread_t tid;
    pthread_create(&tid, NULL, bypass_thread, NULL);
}
