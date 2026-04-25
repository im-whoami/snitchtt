package ai.snitchtt.sample

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import ai.snitchtt.ThreatFlag
import ai.snitchtt.sample.databinding.ItemThreatBinding

class ThreatAdapter(private var items: List<ThreatFlag>) :
    RecyclerView.Adapter<ThreatAdapter.VH>() {

    inner class VH(val b: ItemThreatBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(ItemThreatBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val flag = items[position]
        val ctx  = holder.b.root.context

        holder.b.tvFlagName.text  = flag.name
        holder.b.tvFlagScore.text = "+${flag.score}"
        holder.b.tvFlagDesc.text  = flag.detail()

        val (dotColor, scoreColor) = when {
            flag.score >= 20 -> Pair(R.color.severity_critical, R.color.severity_critical)
            flag.score >= 12 -> Pair(R.color.severity_high,     R.color.severity_high)
            flag.score >= 6  -> Pair(R.color.severity_medium,   R.color.severity_medium)
            else             -> Pair(R.color.severity_low,      R.color.severity_low)
        }
        holder.b.viewDot.setBackgroundColor(ContextCompat.getColor(ctx, dotColor))
        holder.b.tvFlagScore.setTextColor(ContextCompat.getColor(ctx, scoreColor))
    }

    fun update(newItems: List<ThreatFlag>) {
        items = newItems
        notifyDataSetChanged()
    }

    private fun ThreatFlag.detail(): String = when (this) {
        ThreatFlag.FRIDA_AGENT_IN_MAPS    -> "Frida agent library found in /proc/self/maps"
        ThreatFlag.FRIDA_MEMFD_JIT        -> "Frida JIT memfd region detected in memory map"
        ThreatFlag.FRIDA_ZYMBIOTE_SOCKET  -> "Frida zymbiote UNIX socket detected"
        ThreatFlag.FRIDA_GADGET_SYMBOL    -> "Frida gadget native symbol exported"
        ThreatFlag.FRIDA_PORT_FOUND       -> "Frida server responding on a network port"
        ThreatFlag.FRIDA_TRACER_PID       -> "TracerPid != 0 — process is being debugged"
        ThreatFlag.FRIDA_GADGET_TCP       -> "Frida gadget TCP listener found"
        ThreatFlag.FRIDA_STACK_FRAME      -> "Frida stack frame present in call stack"
        ThreatFlag.FRIDA_HELPER_DELETED   -> "Frida helper deleted-but-mapped artifact"
        ThreatFlag.FRIDA_MEMFD_FD         -> "Frida memfd file descriptor open in /proc/self/fd"
        ThreatFlag.XPOSED_IN_MAPS         -> "Xposed/LSPosed library found in memory map"
        ThreatFlag.XPOSED_CLASS_FOUND     -> "Xposed bridge class loaded in JVM"
        ThreatFlag.ZYGISK_ACTIVE          -> "Zygisk module active in process memory"
        ThreatFlag.LSPOSED_SOCKET         -> "LSPosed UNIX socket present"
        ThreatFlag.SSL_HOOK_DETECTED      -> "SSL_write or SSL_read PLT entry is hooked"
        ThreatFlag.HOOK_FRAMEWORK_PRESENT -> "Hook framework (Dobby/shadowhook/whale) in maps"
        ThreatFlag.ANONYMOUS_RWX_REGION   -> "Anonymous RWX memory region — possible injection"
        ThreatFlag.LD_PRELOAD_INJECT      -> "LD_PRELOAD set — library injection detected"
        ThreatFlag.PTRACE_BLOCKED         -> "ptrace(PTRACE_TRACEME) blocked — debugger attached"
        ThreatFlag.CERT_INJECTION         -> "Custom CA cert mount overlay detected"
        ThreatFlag.MAGISK_DATA_FOUND      -> "/data/adb/magisk detected via direct syscall (bypasses Shamiko)"
        ThreatFlag.MAGISK_MOUNT           -> "Magisk bind-mount overlay in mountinfo"
        ThreatFlag.SYSTEM_RW_MOUNTED      -> "/system partition mounted read-write"
        ThreatFlag.SU_BINARY_FOUND        -> "su binary or root app package detected"
        ThreatFlag.SU_EXEC_SUCCESS        -> "su execution succeeded — full root access"
        ThreatFlag.BUSYBOX_FOUND          -> "busybox binary found (typical root environment)"
        ThreatFlag.SELINUX_PERMISSIVE     -> "SELinux is in permissive mode"
        ThreatFlag.TEST_KEYS_BUILD        -> "Build signed with test keys"
        ThreatFlag.DEBUG_BUILD_PROPS      -> "ro.debuggable=1 or eng/userdebug build type"
        ThreatFlag.ADB_ENABLED            -> "ADB debugging is enabled"
        ThreatFlag.DEVELOPER_OPTIONS      -> "Developer options are enabled"
        ThreatFlag.PROXY_CONFIGURED       -> "HTTP/HTTPS proxy configured (MITM risk)"
        ThreatFlag.VPN_ACTIVE             -> "Active VPN tunnel — traffic may be intercepted"
        ThreatFlag.VBMETA_DIGEST_CLEARED  -> "Verified boot vbmeta digest is empty"
        ThreatFlag.BUILD_METRICS_MISMATCH -> "Display metrics don't match claimed device model"
        ThreatFlag.APK_HASH_MISMATCH      -> "APK dex hash mismatch — app may be repackaged"
        ThreatFlag.TIMING_ANOMALY         -> "Syscall timing anomaly — possible hook overhead"
        ThreatFlag.UNKNOWN_CA_IN_STORE    -> "Unknown root CA found in process trust store"
        ThreatFlag.LIBC_OPEN_HOOK         -> "libc open() PLT entry has been redirected"
        ThreatFlag.FRIDA_LATE_INJECT      -> "Frida injected after .so constructor but before JNI_OnLoad — attach-mode confirmed"
        ThreatFlag.FRIDA_THREAD_FOUND     -> "Frida worker thread ('gum-js-loop','gmain','pool-frida') found in /proc/self/task"
        ThreatFlag.LSPOSED_ACTIVE         -> "LSPosed daemon, data directory, or injected DEX detected"
        ThreatFlag.HMA_ACTIVE             -> "PackageManager hook or hidden root packages detected (HMA)"
        else                              -> this.description
    }
}
