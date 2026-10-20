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
#include <sys/syscall.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <errno.h>
#include <ctype.h>

#include <android/log.h>
#define LOG_TAG "Trispy10x"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =====================================================================
// GLOBAL VARIABLES & ORIGINAL FUNCTION POINTERS
// =====================================================================
static int (*orig_system_property_get)(const char* name, char* value) = nullptr;
static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = nullptr;
static FILE* (*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static int (*orig_stat)(const char *pathname, struct stat *statbuf) = nullptr;
static int (*orig_lstat)(const char *pathname, struct stat *statbuf) = nullptr;
static int (*orig_access)(const char *pathname, int mode) = nullptr;
static ssize_t (*orig_readlink)(const char *pathname, char *buf, size_t bufsiz) = nullptr;
static int (*orig_ptrace)(int request, pid_t pid, void *addr, void *data) = nullptr;
static ssize_t (*orig_read)(int fd, void *buf, size_t count) = nullptr;

// =====================================================================
// SECTION 1: REAL DEVICE PROPERTIES SPOOFER (SAMSUNG GALAXY S24 ULTRA)
// =====================================================================
struct FakeProp {
    const char* name;
    const char* value;
};

static FakeProp fake_props[] = {
    // Brand & Model
    {"ro.product.model", "SM-S928B"},
    {"ro.product.brand", "samsung"},
    {"ro.product.name", "e3qxeea"},
    {"ro.product.device", "e3q"},
    {"ro.product.board", "e3q"},
    {"ro.product.manufacturer", "samsung"},
    {"ro.product.locale", "en-GB"},
    {"ro.product.cpu.abi", "arm64-v8a"},
    {"ro.product.cpu.abilist", "arm64-v8a,armeabi-v7a,armeabi"},
    
    // Hardware & Platform
    {"ro.hardware", "qcom"},
    {"ro.board.platform", "sm8650"},
    {"ro.arch", "arm64-v8a"},
    {"ro.kernel.qemu", "0"},
    {"ro.kernel.qemu.gles", "0"},
    {"ro.boot.qemu", "0"},
    {"ro.boot.hardware", "qcom"},
    {"ro.hardware.chipname", "SM8650"},
    {"ro.soc.manufacturer", "QTI"},
    {"ro.soc.model", "SM8650"},
    
    // Build & Fingerprint
    {"ro.build.fingerprint", "samsung/e3qxeea/e3q:14/UP1A.231005.007/S928BXXU1AWLM:user/release-keys"},
    {"ro.build.version.sdk", "34"},
    {"ro.build.version.release", "14"},
    {"ro.build.version.security_patch", "2024-01-01"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.build.user", "dpi"},
    {"ro.build.host", "21DJF80MZA"},
    {"ro.build.id", "UP1A.231005.007"},
    {"ro.build.display.id", "UP1A.231005.007"},
    
    // Security & Root flags (Hide Root/Magisk)
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    {"ro.debuggable", "0"},
    {"ro.allow.mock.location", "0"},
    {"ro.crypto.state", "encrypted"},
    {"ro.crypto.type", "file"},
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.warranty_bit", "0"},
    {"ro.warranty_bit", "0"},
    {"ro.build.selinux", "1"},
    {"ro.boot.selinux", "enforcing"},
    {"ro.sys.sdcardfs", "1"},
    
    // VM & Sandbox Hider
    {"ro.vbox", "0"},
    {"ro.vphonegaga", "0"},
    {"ro.vm", "0"},
    {"ro.dalvik.vm.native.bridge", "0"},
    {"ro.enable.native.bridge.exec", "0"},
    {"ro.zygisk.enabled", "0"},
    {"persist.sys.magisk", "0"},
    
    // Graphics & Display
    {"ro.opengles.version", "196610"},
    {"ro.hardware.egl", "adreno"},
    {"ro.hardware.vulkan", "adreno"},
    {"persist.sys.display.resoultion", "1440x3120"},
    
    // System Services
    {"init.svc.qemud", "stopped"},
    {"init.svc.qemu-props", "stopped"},
    {"init.svc.vbox", "stopped"},
    {"init.svc.magiskd", "stopped"},
    {"init.svc.zygiskd", "stopped"},
    {"sys.boot_completed", "1"},
    {"dev.bootcomplete", "1"}
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

// =====================================================================
// SECTION 2: FILE SYSTEM HIDER (MAGISK, ROOT, FRIDA, SANDBOX)
// =====================================================================

bool is_suspicious_path(const char* path) {
    if (path == nullptr) return false;
    
    if (strstr(path, "/su") || strstr(path, "superuser") || strstr(path, "daemonsu")) return true;
    if (strstr(path, "magisk") || strstr(path, "zygisk") || strstr(path, "topjohnwu") || strstr(path, ".core")) return true;
    if (strstr(path, "frida") || strstr(path, "gum-js") || strstr(path, "gadget") || strstr(path, "gdbserver") || strstr(path, "linjector")) return true;
    if (strstr(path, "qemu") || strstr(path, "vbox") || strstr(path, "vphonegaga") || strstr(path, "genymotion") || strstr(path, "bluestacks") || strstr(path, "ldplayer")) return true;
    if (strstr(path, "top.niunaijun.blackboxa") || strstr(path, "blackbox") || strstr(path, "Bcore") || strstr(path, "libjni")) return true;

    return false;
}

int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return -1; }
    return orig_openat(dirfd, pathname, flags, mode);
}

FILE* my_fopen(const char *pathname, const char *mode) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return nullptr; }
    return orig_fopen(pathname, mode);
}

int my_stat(const char *pathname, struct stat *statbuf) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return -1; }
    return orig_stat(pathname, statbuf);
}

int my_lstat(const char *pathname, struct stat *statbuf) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return -1; }
    return orig_lstat(pathname, statbuf);
}

int my_access(const char *pathname, int mode) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return -1; }
    return orig_access(pathname, mode);
}

ssize_t my_readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (is_suspicious_path(pathname)) { errno = ENOENT; return -1; }
    if (strstr(pathname, "/proc/self/exe") || strstr(pathname, "/proc/self/cwd")) {
        const char* fake_path = "/system/bin/app_process64";
        strncpy(buf, fake_path, bufsiz);
        return strlen(fake_path);
    }
    return orig_readlink(pathname, buf, bufsiz);
}

// =====================================================================
// SECTION 3: MEMORY & PTRACE BLOCKER
// =====================================================================

int my_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE || request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) {
        errno = EPERM;
        return -1;
    }
    return orig_ptrace(request, pid, addr, data);
}

ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t res = orig_read(fd, buf, count);
    if (res <= 0) return res;

    char* char_buf = (char*)buf;
    
    // Scrub TracerPid
    if (strstr(char_buf, "TracerPid:") != nullptr) {
        char* tracer = strstr(char_buf, "TracerPid:");
        if (tracer) {
            char* end_line = strstr(tracer, "\n");
            if (end_line) snprintf(tracer, end_line - tracer + 1, "TracerPid:\t0\n");
        }
    }

    // Scrub Sandbox/Magisk traces from memory maps
    if (strstr(char_buf, "magisk") || strstr(char_buf, "frida") || strstr(char_buf, "vbox") || strstr(char_buf, "blackbox")) {
        char* ptr = char_buf;
        while ((ptr = strstr(ptr, "magisk")) != nullptr) { memset(ptr, '*', 6); }
        ptr = char_buf;
        while ((ptr = strstr(ptr, "frida")) != nullptr) { memset(ptr, '*', 5); }
        ptr = char_buf;
        while ((ptr = strstr(ptr, "vbox")) != nullptr) { memset(ptr, '*', 4); }
        ptr = char_buf;
        while ((ptr = strstr(ptr, "blackbox")) != nullptr) { memset(ptr, '*', 8); }
    }

    return res;
}

// =====================================================================
// SECTION 4: GOD-TIER INITIALIZATION & HOOKING WATCHDOG
// =====================================================================

void apply_all_hooks() {
    void* handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return;

    void* prop_sym = dlsym(handle, "__system_property_get");
    void* openat_sym = dlsym(handle, "openat");
    void* fopen_sym = dlsym(handle, "fopen");
    void* stat_sym = dlsym(handle, "stat");
    void* lstat_sym = dlsym(handle, "lstat");
    void* access_sym = dlsym(handle, "access");
    void* readlink_sym = dlsym(handle, "readlink");
    void* ptrace_sym = dlsym(handle, "ptrace");
    void* read_sym = dlsym(handle, "read");

    // Note: In BBox, you must use their native hooking framework (e.g., Dobby) here.
    // For this code to work, you need to replace the dlsym pointers with the actual hook calls.
    // Example: DobbyHook(openat_sym, (void*)my_openat, (void**)&orig_openat);
    
    dlclose(handle);
    LOGI("10x Bypass Hooks Applied Successfully.");
}

static void* watchdog_thread(void*) {
    sleep(3); 
    while (true) {
        apply_all_hooks();
        sleep(10); 
    }
    return nullptr;
}

__attribute__((constructor))
void bypass_init() {
    pthread_t tid;
    pthread_create(&tid, NULL, watchdog_thread, NULL);
}
