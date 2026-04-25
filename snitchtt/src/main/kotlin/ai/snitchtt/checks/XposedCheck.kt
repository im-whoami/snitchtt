package ai.snitchtt.checks

import ai.snitchtt.ThreatFlag
import android.content.Context
import dalvik.system.BaseDexClassLoader

internal object XposedCheck {

    private val XPOSED_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.callbacks.XC_MethodHook",
        "de.robv.android.xposed.XC_MethodReplacement",
        "org.lsposed.lspatch.share.LSPConfig",
        "org.lsposed.lspatch.loader.LSPApplication",
        "io.github.lspluginmanager.ILSPManagerService",
    )

    fun check(context: Context): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()

        /* Class presence */
        for (cls in XPOSED_CLASSES) {
            try { Class.forName(cls); flags += ThreatFlag.XPOSED_CLASS_FOUND; break }
            catch (_: ClassNotFoundException) {}
        }

        /* Stack trace contamination */
        try { throw Exception() } catch (e: Exception) {
            for (frame in e.stackTrace) {
                val cn = frame.className
                if (cn.startsWith("de.robv.android.xposed") ||
                    cn.startsWith("org.lsposed") ||
                    cn.startsWith("io.github.lspluginmanager") ||
                    cn.startsWith("com.elderdrivers.riru")) {
                    flags += ThreatFlag.XPOSED_CLASS_FOUND; break
                }
            }
        }

        /* Classloader DEX path scan — LSPosed injects its DEX into the app
         * classloader; the path shows up in BaseDexClassLoader.toString() */
        var cl: ClassLoader? = context.classLoader
        while (cl != null) {
            if (cl is BaseDexClassLoader) {
                val s = cl.toString()
                if (s.contains("lspd") ||
                    s.contains("lsposed") ||
                    s.contains("xposed") ||
                    (s.contains("/data/adb/") && (s.contains(".dex") || s.contains(".apk")))) {
                    flags += ThreatFlag.LSPOSED_ACTIVE
                    break
                }
            }
            cl = cl.parent
        }

        return flags
    }
}
