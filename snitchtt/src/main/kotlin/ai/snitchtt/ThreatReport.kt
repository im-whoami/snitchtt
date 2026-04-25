package ai.snitchtt

data class ThreatReport(
    val flags: Set<ThreatFlag>,
    val riskScore: Int,
    val fridaPort: Int = -1,
    val tracerPid: Int = 0,
    val timestamp: Long = System.currentTimeMillis()
) {
    /** Terminate session immediately. */
    val isCompromised: Boolean get() = riskScore >= 20

    /** Require step-up authentication. */
    val requiresStepUp: Boolean get() = riskScore in 8..19

    /** Device appears clean. */
    val isClean: Boolean get() = riskScore < 4

    fun summary(): String = buildString {
        appendLine("=== Snitchtt.ai Threat Report ===")
        appendLine("Risk score : $riskScore")
        appendLine("Status     : ${when { isCompromised -> "COMPROMISED"; requiresStepUp -> "SUSPICIOUS"; else -> "CLEAN" }}")
        if (flags.isEmpty()) {
            appendLine("No threats detected.")
        } else {
            appendLine("Detected (${flags.size}):")
            flags.sortedByDescending { it.score }.forEach {
                appendLine("  [${it.score}] ${it.name} — ${it.description}")
            }
        }
        if (fridaPort != -1) appendLine("Frida port : $fridaPort")
        if (tracerPid != 0)  appendLine("TracerPid  : $tracerPid")
    }
}
