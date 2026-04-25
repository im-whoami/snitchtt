package ai.snitchtt

enum class ThreatFlag(val score: Int, val description: String) {

    /* ── Frida — definitive (score ≥ 20 = kill session alone) ── */
    FRIDA_AGENT_IN_MAPS     (20, "frida-agent mapped into process memory"),
    FRIDA_HELPER_DELETED    (20, "frida-helper DEX mapped then deleted"),
    FRIDA_GADGET_SYMBOL     (20, "frida_gadget_load/gum symbol found via dlsym"),
    FRIDA_TRACER_PID        (20, "TracerPid ≠ 0 — process is being traced"),
    PTRACE_BLOCKED          (20, "ptrace(TRACEME) blocked — external debugger attached"),
    CERT_INJECTION          (20, "tmpfs mounted over APEX conscrypt cert dir"),
    SSL_HOOK_DETECTED       (20, "SSL_write or SSL_read PLT hook detected"),
    APK_HASH_MISMATCH       (20, "APK DEX hash doesn't match build-time pin"),
    LD_PRELOAD_INJECT       (18, "LD_PRELOAD or LD_LIBRARY_PATH set to injected lib"),
    FRIDA_MEMFD_JIT         (18, "Frida GumJS JIT heap detected (>8 MB memfd)"),
    FRIDA_ZYMBIOTE_SOCKET   (18, "Frida spawn-mode zymbiote abstract socket"),
    FRIDA_PORT_FOUND        (18, "Port responds to Frida D-Bus handshake"),
    FRIDA_MEMFD_FD          (18, "Frida memfd found in /proc/self/fd"),
    FRIDA_STACK_FRAME       (15, "Frida frame detected in native call stack"),
    HOOK_FRAMEWORK_PRESENT  (15, "Dobby / shadowhook / whale hooking lib in maps"),

    /* ── LSPosed / Xposed / Zygisk ── */
    FRIDA_LATE_INJECT       (20, "Frida injected between .so constructor and JNI_OnLoad — late attach"),
    FRIDA_THREAD_FOUND      (15, "Frida worker thread name in /proc/self/task — attach mode"),
    XPOSED_CLASS_FOUND      (12, "XposedBridge class present in classloader"),
    XPOSED_IN_MAPS          (12, "xposed/lsposed path in /proc/self/maps"),
    LSPOSED_SOCKET          (12, "LSPosed IPC socket detected"),
    LSPOSED_ACTIVE          (12, "LSPosed daemon/module/DEX injection detected"),
    FRIDA_GADGET_TCP        (12, "Unexpected TCP LISTEN port in process namespace"),
    ZYGISK_ACTIVE           (10, "libzygisk.so inherited from zygote"),
    HMA_ACTIVE              (10, "PackageManager hook detected — Hide My Applist active"),

    /* ── Certificate / SSL ── */
    UNKNOWN_CA_IN_STORE     (10, "Non-public root CA in process trust store"),

    /* ── Root ── */
    MAGISK_DATA_FOUND       (15, "/data/adb/magisk exists — Magisk installed"),
    MAGISK_MOUNT            (12, "Magisk tmpfs on /debug_ramdisk"),
    SYSTEM_RW_MOUNTED       (10, "System partition mounted read-write"),
    SU_EXEC_SUCCESS         (15, "su -c id returned uid=0"),
    SU_BINARY_FOUND         ( 8, "su binary found on filesystem"),
    LIBC_OPEN_HOOK          (12, "libc open() PLT entry redirected"),
    ANONYMOUS_RWX_REGION    ( 8, "Anonymous rwxp memory (injected shellcode)"),
    SELINUX_PERMISSIVE      ( 8, "SELinux in permissive mode"),

    /* ── Build / Environment ── */
    DEBUG_BUILD_PROPS       ( 8, "ro.debuggable=1 or ro.build.type=eng/userdebug"),
    TEST_KEYS_BUILD         ( 8, "Build signed with test-keys"),
    TIMING_ANOMALY          ( 6, "Syscall timing anomaly — possible hook overhead"),
    BUSYBOX_FOUND           ( 4, "BusyBox binary found"),

    /* ── Soft signals (used for step-up auth) ── */
    ADB_ENABLED             ( 5, "USB debugging enabled"),
    DEVELOPER_OPTIONS       ( 4, "Developer options enabled"),
    PROXY_CONFIGURED        ( 4, "HTTP/S proxy configured"),
    VPN_ACTIVE              ( 4, "Active VPN tunnel detected"),
    VBMETA_DIGEST_CLEARED   ( 3, "ro.boot.vbmeta.digest empty (Integrity Box)"),
    BUILD_METRICS_MISMATCH  ( 5, "Hardware metrics don't match claimed Build.MODEL");
}
