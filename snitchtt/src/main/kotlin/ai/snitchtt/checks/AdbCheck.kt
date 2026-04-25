package ai.snitchtt.checks

import android.content.Context
import android.provider.Settings
import ai.snitchtt.ThreatFlag
import java.net.Socket

internal object AdbCheck {
    fun check(context: Context): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()
        val cr = context.contentResolver

        if (Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) != 0)
            flags += ThreatFlag.ADB_ENABLED
        if (Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0)
            flags += ThreatFlag.DEVELOPER_OPTIONS

        try { Socket("127.0.0.1", 5037).use { flags += ThreatFlag.ADB_ENABLED } }
        catch (_: Exception) {}

        return flags
    }
}
