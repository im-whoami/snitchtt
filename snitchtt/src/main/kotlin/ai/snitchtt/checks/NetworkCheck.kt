package ai.snitchtt.checks

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import ai.snitchtt.ThreatFlag

internal object NetworkCheck {

    fun check(context: Context): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return flags

        detectVpn(cm, flags)
        detectProxy(cm, context, flags)

        return flags
    }

    private fun detectVpn(cm: ConnectivityManager, flags: MutableSet<ThreatFlag>) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                flags += ThreatFlag.VPN_ACTIVE
                return
            }
        }
        /* Fallback for API < 23 */
        try {
            @Suppress("DEPRECATION")
            val info = cm.getNetworkInfo(17 /* TYPE_VPN */)
            if (info?.isConnected == true) flags += ThreatFlag.VPN_ACTIVE
        } catch (_: Exception) {}
    }

    private fun detectProxy(
        cm: ConnectivityManager,
        context: Context,
        flags: MutableSet<ThreatFlag>
    ) {
        /* Android system proxy (ConnectivityManager) */
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val proxy = cm.defaultProxy
                if (!proxy?.host.isNullOrBlank()) {
                    flags += ThreatFlag.PROXY_CONFIGURED
                    return
                }
            } catch (_: Exception) {}
        }

        /* Global proxy set via ADB / MDM */
        val host = Settings.Global.getString(
            context.contentResolver, "global_http_proxy_host")
        if (!host.isNullOrBlank() && host != "null")
            flags += ThreatFlag.PROXY_CONFIGURED
    }
}
