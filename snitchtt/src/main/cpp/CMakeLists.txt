cmake_minimum_required(VERSION 3.22.1)
project(snitchtt C)

# ── libsna.so — Frida / timing / thread detection ────────────────────────────
add_library(sna SHARED
    hunter_entry.c
    maps_scan.c
    frida_detect.c
    port_probe.c
    stack_check.c
    fd_scan.c
    thread_scan.c
    timing.c
)

target_compile_options(sna PRIVATE
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -O2
    -Wall
)

target_link_options(sna PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
    -Wl,--export-dynamic-symbol=sna_e
)

target_link_libraries(sna
    log
    dl
    unwind
)

# ── libsnb.so — Root / mount / PLT / env / LSPosed detection ─────────────────
add_library(snb SHARED
    guard_entry.c
    root_check.c
    mount_check.c
    plt_check.c
    env_check.c
    lsposed_check.c
    adb_native.c
    build_native.c
)

target_compile_options(snb PRIVATE
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -O2
    -Wall
)

target_link_options(snb PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
    -Wl,--export-dynamic-symbol=snb_e
)

target_link_libraries(snb
    log
    dl
)

# ── libsnitchtt.so — JNI bridge (thin layer; dlopen's sna + snb at runtime) ──
add_library(snitchtt SHARED
    snitchtt_jni.c
)

target_compile_options(snitchtt PRIVATE
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -O2
    -Wall
)

target_link_options(snitchtt PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
    -Wl,--export-dynamic-symbol=JNI_OnLoad
)

target_link_libraries(snitchtt
    android
    log
    dl
)
