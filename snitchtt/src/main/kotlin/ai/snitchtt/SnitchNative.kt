package ai.snitchtt

import android.util.Log

/**
 * JNI bridge to libsnitchtt.so.
 *
 * Functions are registered in JNI_OnLoad via RegisterNatives — their names
 * do NOT appear as exported symbols in the .so, making Frida name-based hooks
 * fail silently. The only exported symbol is JNI_OnLoad.
 */
internal object SnitchNative {

    init {
        try {
            System.loadLibrary("snitchtt")
        } catch (e: UnsatisfiedLinkError) {
            Log.e("Snitchtt", "Native lib missing: ${e.message}")
        }
    }

    /** bit 0=frida_agent, 1=memfd, 2=zymbiote, 3=gadget, 4=zygisk, 5=xposed, 6=anon_rwx, 7=hook_fw, 8=deleted */
    @JvmStatic external fun nativeScanMaps(): Int

    /** bit 0=tracerPid, 1=zymbiote_sock, 2=gadget_tcp, 3=gadget_sym, 4=gum_sym, 5=lsposed_sock */
    @JvmStatic external fun nativeDetectFrida(): Int

    /** Returns Frida port or -1 */
    @JvmStatic external fun nativeScanPort(): Int

    /** bit 0=conscrypt_tmpfs, 1=magisk_mount, 2=system_rw */
    @JvmStatic external fun nativeCheckMounts(): Int

    /** bit 0=su_binary, 1=busybox, 2=selinux_perm, 3=debuggable, 4=insecure, 5=eng_build */
    @JvmStatic external fun nativeCheckRoot(): Int

    @JvmStatic external fun nativeCheckPlt(): Boolean
    @JvmStatic external fun nativeCheckStack(): Boolean
    @JvmStatic external fun nativeCheckFd(): Boolean

    /** bit 0=ld_preload, 1=ptrace_blocked */
    @JvmStatic external fun nativeCheckEnv(): Int

    @JvmStatic external fun nativeGetBaseline(): Long
    @JvmStatic external fun nativeCheckTiming(baseline: Long): Boolean
    @JvmStatic external fun nativeStartMonitor(intervalSec: Int)

    /** bit 24=frida_thread in maps_bits from sna */
    @JvmStatic external fun nativeCheckThreads(): Boolean

    /** bit 0=lspd_process, 1=lspd_data, 2=mod_lsposed, 3=mod_shamiko, 4=mod_hma, 5=mod_zgnxt */
    @JvmStatic external fun nativeCheckLsposed(): Int

    /** True if new Frida/hook bits appeared between constructor and first JNI scan = attach-mode */
    @JvmStatic external fun nativeCheckLateInject(): Boolean

    /** bit 0=adbd_running, 1=adb_keys_exist, 2=adb_port_open — bypasses Settings.Secure hook */
    @JvmStatic external fun nativeCheckAdbNative(): Int

    /** bit 0=vbmeta_cleared, 1=bootloader_unlocked, 2=test_keys, 3=eng_or_userdebug — bypasses android.os.Build hook */
    @JvmStatic external fun nativeCheckBuildNative(): Int

    /** Called by native monitor thread */
    @JvmStatic
    fun onAlert(score: Int) {
        Snitchtt.notifyAlert(score)
    }
}
