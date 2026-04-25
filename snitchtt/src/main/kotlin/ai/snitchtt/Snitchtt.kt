package ai.snitchtt

import android.content.Context
import android.os.Build
import android.util.Log
import ai.snitchtt.checks.*
import kotlinx.coroutines.*
import java.util.concurrent.CopyOnWriteArrayList
import java.util.zip.ZipFile
import java.security.MessageDigest

class Snitchtt private constructor(
    private val context: Context,
    private val config: SnitchConfig
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val listeners = CopyOnWriteArrayList<(ThreatReport) -> Unit>()

    companion object {
        @Volatile private var instance: Snitchtt? = null

        fun init(context: Context, config: SnitchConfig = SnitchConfig()): Snitchtt =
            instance ?: synchronized(this) {
                instance ?: Snitchtt(context.applicationContext, config).also {
                    instance = it
                    SnitchNative  // touch native lib
                    if (config.enableContinuousMonitor)
                        SnitchNative.nativeStartMonitor(config.monitorIntervalSeconds)
                }
            }

        fun getInstance(): Snitchtt =
            instance ?: error("Snitchtt.init() must be called before getInstance()")

        internal fun notifyAlert(score: Int) {
            instance?.scope?.launch {
                val report = instance?.scan() ?: return@launch
                instance?.listeners?.forEach { it(report) }
            }
        }
    }

    suspend fun scan(): ThreatReport = withContext(Dispatchers.IO) {
        val flags = mutableSetOf<ThreatFlag>()
        var fridaPort = -1
        var tracerPid = 0

        /* ── Native: late-inject (constructor vs JNI_OnLoad delta) ───── */
        if (config.checkFridaMaps) {
            if (SnitchNative.nativeCheckLateInject()) flags += ThreatFlag.FRIDA_LATE_INJECT
        }

        /* ── Native: maps ─────────────────────────────────────────── */
        if (config.checkFridaMaps) {
            val bits = SnitchNative.nativeScanMaps()
            if (bits and 0x001 != 0) flags += ThreatFlag.FRIDA_AGENT_IN_MAPS
            if (bits and 0x002 != 0) flags += ThreatFlag.FRIDA_MEMFD_JIT
            if (bits and 0x004 != 0) flags += ThreatFlag.FRIDA_ZYMBIOTE_SOCKET
            if (bits and 0x008 != 0) flags += ThreatFlag.FRIDA_GADGET_SYMBOL
            if (bits and 0x010 != 0) flags += ThreatFlag.ZYGISK_ACTIVE
            if (bits and 0x020 != 0) flags += ThreatFlag.XPOSED_IN_MAPS
            if (bits and 0x040 != 0) flags += ThreatFlag.ANONYMOUS_RWX_REGION
            if (bits and 0x080 != 0) flags += ThreatFlag.HOOK_FRAMEWORK_PRESENT
            if (bits and 0x100 != 0) flags += ThreatFlag.FRIDA_HELPER_DELETED
            if (bits and 0x200 != 0) flags += ThreatFlag.FRIDA_LATE_INJECT
        }

        /* ── Native: Frida process checks ─────────────────────────── */
        if (config.checkFridaTracer) {
            val bits = SnitchNative.nativeDetectFrida()
            if (bits and 0x01 != 0) { flags += ThreatFlag.FRIDA_TRACER_PID; tracerPid = 1 }
            if (bits and 0x02 != 0) flags += ThreatFlag.FRIDA_ZYMBIOTE_SOCKET
            if (bits and 0x04 != 0) flags += ThreatFlag.FRIDA_GADGET_TCP
            if (bits and 0x08 != 0) flags += ThreatFlag.FRIDA_GADGET_SYMBOL
            if (bits and 0x20 != 0) flags += ThreatFlag.LSPOSED_SOCKET
        }

        /* ── Native: port scan ────────────────────────────────────── */
        if (config.checkFridaPort) {
            fridaPort = SnitchNative.nativeScanPort()
            if (fridaPort != -1) flags += ThreatFlag.FRIDA_PORT_FOUND
        }

        /* ── Native: mounts ───────────────────────────────────────── */
        if (config.checkMounts) {
            val bits = SnitchNative.nativeCheckMounts()
            if (bits and 0x01 != 0) flags += ThreatFlag.CERT_INJECTION
            if (bits and 0x02 != 0) flags += ThreatFlag.MAGISK_MOUNT
            if (bits and 0x04 != 0) flags += ThreatFlag.SYSTEM_RW_MOUNTED
        }

        /* ── Native: root props ───────────────────────────────────── */
        if (config.checkRoot) {
            val bits = SnitchNative.nativeCheckRoot()
            if (bits and 0x001 != 0) flags += ThreatFlag.SU_BINARY_FOUND
            if (bits and 0x002 != 0) flags += ThreatFlag.BUSYBOX_FOUND
            if (bits and 0x004 != 0) flags += ThreatFlag.SELINUX_PERMISSIVE
            if (bits and 0x008 != 0) flags += ThreatFlag.DEBUG_BUILD_PROPS
            if (bits and 0x010 != 0) flags += ThreatFlag.DEBUG_BUILD_PROPS
            if (bits and 0x020 != 0) flags += ThreatFlag.DEBUG_BUILD_PROPS
            if (bits and 0x040 != 0) flags += ThreatFlag.MAGISK_DATA_FOUND
            if (bits and 0x080 != 0) flags += ThreatFlag.MAGISK_MOUNT
            if (bits and 0x100 != 0) flags += ThreatFlag.SU_BINARY_FOUND
            if (bits and 0x200 != 0) flags += ThreatFlag.MAGISK_MOUNT
            if (bits and 0x400 != 0) flags += ThreatFlag.MAGISK_MOUNT
        }

        /* ── Native: PLT hooks ────────────────────────────────────── */
        if (config.checkPltHooks) {
            if (SnitchNative.nativeCheckPlt()) flags += ThreatFlag.SSL_HOOK_DETECTED
        }

        /* ── Native: stack ────────────────────────────────────────── */
        if (config.checkFridaStack) {
            if (SnitchNative.nativeCheckStack()) flags += ThreatFlag.FRIDA_STACK_FRAME
        }

        /* ── Native: fd memfd scan ────────────────────────────────── */
        if (config.checkFridaFd) {
            if (SnitchNative.nativeCheckFd()) flags += ThreatFlag.FRIDA_MEMFD_FD
        }

        /* ── Native: env / ptrace ─────────────────────────────────── */
        if (config.checkEnv) {
            val bits = SnitchNative.nativeCheckEnv()
            if (bits and 0x01 != 0) flags += ThreatFlag.LD_PRELOAD_INJECT
            if (bits and 0x02 != 0) flags += ThreatFlag.PTRACE_BLOCKED
        }

        /* ── Native: Frida thread scan (attach-mode) ──────────────── */
        if (config.checkFridaTracer) {
            if (SnitchNative.nativeCheckThreads()) flags += ThreatFlag.FRIDA_THREAD_FOUND
        }

        /* ── Native: LSPosed module/process/data scan ─────────────── */
        if (config.checkLsposed) {
            if (SnitchNative.nativeCheckLsposed() != 0) flags += ThreatFlag.LSPOSED_ACTIVE
        }

        /* ── Native: ADB (bypasses Settings.Secure Java hook) ────── */
        if (config.checkAdb) {
            val adbBits = SnitchNative.nativeCheckAdbNative()
            if (adbBits and 0x01 != 0) flags += ThreatFlag.ADB_ENABLED       // adbd_running
            if (adbBits and 0x02 != 0) flags += ThreatFlag.ADB_ENABLED       // adb_keys_exist
            if (adbBits and 0x04 != 0) flags += ThreatFlag.ADB_ENABLED       // adb_port_open TCP 5037
        }

        /* ── Native: build props (bypasses android.os.Build hook) ── */
        if (config.checkBuildSpoof) {
            val bldBits = SnitchNative.nativeCheckBuildNative()
            if (bldBits and 0x01 != 0) flags += ThreatFlag.VBMETA_DIGEST_CLEARED  // vbmeta cleared
            if (bldBits and 0x02 != 0) flags += ThreatFlag.VBMETA_DIGEST_CLEARED  // bootloader orange/yellow
            if (bldBits and 0x04 != 0) flags += ThreatFlag.TEST_KEYS_BUILD         // test-keys
            if (bldBits and 0x08 != 0) flags += ThreatFlag.DEBUG_BUILD_PROPS       // eng/userdebug
        }

        /* ── Native: timing ───────────────────────────────────────── */
        if (config.checkTimingAnomaly) {
            val base = if (config.baselineNsPerCall > 0) config.baselineNsPerCall
                       else SnitchNative.nativeGetBaseline()
            if (SnitchNative.nativeCheckTiming(base)) flags += ThreatFlag.TIMING_ANOMALY
        }

        /* ── Kotlin: Xposed / LSPosed ─────────────────────────────── */
        if (config.checkXposed) flags += XposedCheck.check(context)

        /* ── Kotlin: ADB / dev options ────────────────────────────── */
        if (config.checkAdb) flags += AdbCheck.check(context)

        /* ── Kotlin: VPN / Proxy ──────────────────────────────────── */
        if (config.checkNetwork) flags += NetworkCheck.check(context)

        /* ── Kotlin: Build spoof ──────────────────────────────────── */
        if (config.checkBuildSpoof) flags += BuildCheck.check(context)

        /* ── Kotlin: HMA (PackageManager hook) ───────────────────── */
        if (config.checkHma) flags += HmaCheck.check(context)

        /* ── Kotlin: su exec + known root apps ───────────────────── */
        if (config.checkRoot) {
            flags += RootCheck.checkSuExec()
            flags += RootCheck.checkKnownRootApps(context.packageManager)
        }

        /* ── Kotlin: CA trust store ───────────────────────────────── */
        if (config.knownCaSpkiHashes.isNotEmpty())
            flags += CertCheck.findUnknownCAs(config.knownCaSpkiHashes)

        /* ── Kotlin: APK integrity ────────────────────────────────── */
        if (config.checkApkIntegrity && config.dexHashes.isNotEmpty()) {
            if (apkTampered(config.dexHashes)) flags += ThreatFlag.APK_HASH_MISMATCH
        }

        /* ── Score ────────────────────────────────────────────────── */
        val report = ThreatReport(
            flags     = flags,
            riskScore = flags.sumOf { it.score },
            fridaPort = fridaPort,
            tracerPid = tracerPid
        )
        Log.w("SnitchScan", report.summary())
        report
    }

    fun startMonitoring(onThreat: (ThreatReport) -> Unit) { listeners.add(onThreat) }
    fun stopMonitoring(onThreat: (ThreatReport) -> Unit)  { listeners.remove(onThreat) }

    private fun apkTampered(expected: List<String>): Boolean = try {
        ZipFile(context.packageCodePath).use { zip ->
            val md = MessageDigest.getInstance("SHA-256")
            zip.entries().asSequence()
                .filter { it.name.startsWith("classes") && it.name.endsWith(".dex") }
                .forEachIndexed { idx, entry ->
                    md.reset()
                    zip.getInputStream(entry).use { ins ->
                        val buf = ByteArray(8192); var n: Int
                        while (ins.read(buf).also { n = it } > 0) md.update(buf, 0, n)
                    }
                    val actual = md.digest().joinToString("") { "%02x".format(it) }
                    if (idx >= expected.size || actual != expected[idx]) return true
                }
        }
        false
    } catch (_: Exception) { false }
}
