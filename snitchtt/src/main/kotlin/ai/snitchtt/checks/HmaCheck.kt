package ai.snitchtt.checks

import ai.snitchtt.ThreatFlag
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock

internal object HmaCheck {

    private const val TIMING_SAMPLES   = 8
    private const val HOOK_RATIO       = 6L   /* hooked calls ≥6× slower than baseline */
    private const val BASELINE_SAMPLES = 4

    fun check(context: Context): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()
        val pm = context.packageManager

        /* ── PM call timing anomaly ───────────────────────────────────────
         * HMA hooks getInstalledPackages via LSPosed; the hook adds overhead.
         * Measure a few cheap calls to get a nanosecond-level comparison.   */
        val baseline = measurePmCallNs(pm, BASELINE_SAMPLES)
        val check    = measurePmCallNs(pm, TIMING_SAMPLES)
        if (baseline > 0 && check > baseline * HOOK_RATIO) {
            flags += ThreatFlag.HMA_ACTIVE
        }

        /* ── Root-visible packages hidden from PM ─────────────────────────
         * If root checks already fire (magisk data found) but known root app
         * packages are NOT visible via PM, HMA's package hide feature is on. */
        val knownRootPkgs = listOf(
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "com.fox2code.mmm",
            "com.nikitin.rocketroot",
            "eu.chainfire.supersu"
        )
        val pmVisible = knownRootPkgs.count { pkg ->
            try { pm.getPackageInfo(pkg, 0); true } catch (_: PackageManager.NameNotFoundException) { false }
        }
        val syscallVisible = countRootPkgsDirect(knownRootPkgs)
        if (syscallVisible > pmVisible + 1) {
            flags += ThreatFlag.HMA_ACTIVE
        }

        return flags
    }

    private fun measurePmCallNs(pm: PackageManager, n: Int): Long {
        var total = 0L
        repeat(n) {
            val t0 = SystemClock.elapsedRealtimeNanos()
            try { pm.getPackageInfo("android", 0) } catch (_: Exception) {}
            total += SystemClock.elapsedRealtimeNanos() - t0
        }
        return if (n > 0) total / n else 0L
    }

    private fun countRootPkgsDirect(pkgs: List<String>): Int {
        var count = 0
        for (pkg in pkgs) {
            val path = "/data/data/$pkg"
            val f = java.io.File(path)
            if (f.exists()) count++
        }
        return count
    }
}
