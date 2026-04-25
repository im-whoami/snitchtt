package ai.snitchtt.checks

import ai.snitchtt.ThreatFlag
import android.os.Build
import java.util.concurrent.TimeUnit

internal object RootCheck {

    fun checkSuExec(): Set<ThreatFlag> {
        val paths = listOf("su", "/system/xbin/su", "/system/bin/su", "/sbin/su",
                           "/data/local/su", "/data/local/xbin/su")
        for (path in paths) {
            try {
                val p = Runtime.getRuntime().exec(arrayOf(path, "-c", "id"))
                if (p.waitFor(3, TimeUnit.SECONDS) && p.exitValue() == 0) {
                    val out = p.inputStream.bufferedReader().readLine() ?: ""
                    if (out.contains("uid=0")) return setOf(ThreatFlag.SU_EXEC_SUCCESS)
                }
            } catch (_: Exception) {}
        }
        return emptySet()
    }

    fun checkTestKeys(): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()
        if (Build.TAGS?.contains("test-keys") == true)
            flags += ThreatFlag.TEST_KEYS_BUILD
        return flags
    }

    fun checkKnownRootApps(pm: android.content.pm.PackageManager): Set<ThreatFlag> {
        val rootPkgs = listOf(
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "com.fox2code.mmm",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.zachspong.temprootremovejb",
            "me.bmax.apatch",
        )
        for (pkg in rootPkgs) {
            try {
                pm.getPackageInfo(pkg, 0)
                return setOf(ThreatFlag.SU_BINARY_FOUND) // reuse closest flag
            } catch (_: Exception) {}
        }
        return emptySet()
    }
}
