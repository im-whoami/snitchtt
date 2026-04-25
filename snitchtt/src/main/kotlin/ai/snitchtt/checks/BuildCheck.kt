package ai.snitchtt.checks

import android.content.Context
import android.os.Build
import android.util.DisplayMetrics
import android.view.WindowManager
import ai.snitchtt.ThreatFlag

internal object BuildCheck {

    private val MODEL_SPECS = mapOf(
        "Pixel 8"           to Triple(1080, 2400, 428),
        "Pixel 8 Pro"       to Triple(1344, 2992, 489),
        "Pixel 9"           to Triple(1080, 2424, 422),
        "Pixel 9 Pro"       to Triple(1280, 2856, 495),
        "Pixel 9 Pro Fold"  to Triple(2076, 2152, 408),
        "Pixel 9 Pro XL"    to Triple(1344, 2992, 489),
        "Pixel 7"           to Triple(1080, 2400, 416),
        "Pixel 7 Pro"       to Triple(1440, 3120, 512),
        "Pixel 7a"          to Triple(1080, 2400, 429),
        "Pixel 6"           to Triple(1080, 2400, 411),
        "Pixel 6 Pro"       to Triple(1440, 3120, 512),
        "Pixel 6a"          to Triple(1080, 2400, 429),
    )

    fun check(context: Context): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()

        /* Hardware metrics vs claimed model */
        val specs = MODEL_SPECS[Build.MODEL]
        if (specs != null) {
            val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val dm = DisplayMetrics()
            @Suppress("DEPRECATION") wm.defaultDisplay.getRealMetrics(dm)
            val (expW, expH, expDpi) = specs
            if (dm.widthPixels  !in (expW  - 30)..(expW  + 30) ||
                dm.heightPixels !in (expH  - 30)..(expH  + 30) ||
                dm.densityDpi   !in (expDpi - 20)..(expDpi + 20))
                flags += ThreatFlag.BUILD_METRICS_MISMATCH
        }

        /* vbmeta digest + verified boot state */
        try {
            val cls = Class.forName("android.os.SystemProperties")
            val get = cls.getMethod("get", String::class.java, String::class.java)

            val digest = get.invoke(null, "ro.boot.vbmeta.digest", "") as String
            if (digest.isEmpty()) flags += ThreatFlag.VBMETA_DIGEST_CLEARED

            /* orange = unlocked bootloader, yellow = self-signed key — both indicate
             * that the device may have been modified below the OS level. */
            val vbs = get.invoke(null, "ro.boot.verifiedbootstate", "green") as String
            if (vbs == "orange" || vbs == "yellow")
                flags += ThreatFlag.VBMETA_DIGEST_CLEARED
        } catch (_: Exception) {}

        /* Java-level proxy (set by JVM or app framework — different from system proxy) */
        val jvmProxy = System.getProperty("https.proxyHost") ?: System.getProperty("http.proxyHost")
        if (!jvmProxy.isNullOrEmpty()) flags += ThreatFlag.PROXY_CONFIGURED

        /* Test keys */
        if (Build.TAGS?.contains("test-keys") == true)
            flags += ThreatFlag.TEST_KEYS_BUILD

        return flags
    }
}
