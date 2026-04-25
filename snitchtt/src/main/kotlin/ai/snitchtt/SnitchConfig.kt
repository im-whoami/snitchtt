package ai.snitchtt

data class SnitchConfig(
    val checkFridaMaps:         Boolean = true,
    val checkFridaPort:         Boolean = true,
    val checkFridaTracer:       Boolean = true,
    val checkFridaStack:        Boolean = true,
    val checkFridaFd:           Boolean = true,
    val checkMounts:            Boolean = true,
    val checkNetwork:           Boolean = true,
    val checkPltHooks:          Boolean = true,
    val checkRoot:              Boolean = true,
    val checkEnv:               Boolean = true,
    val checkTimingAnomaly:     Boolean = true,
    val checkXposed:            Boolean = true,
    val checkLsposed:           Boolean = true,
    val checkHma:               Boolean = true,
    val checkAdb:               Boolean = true,
    val checkBuildSpoof:        Boolean = true,
    val checkApkIntegrity:      Boolean = false,
    val enableContinuousMonitor:Boolean = true,
    val monitorIntervalSeconds: Int     = 15,
    val dexHashes:              List<String> = emptyList(),
    val baselineNsPerCall:      Long    = 0L,
    /** SPKI SHA-256 hashes of known-good root CAs. Empty = skip CA check. */
    val knownCaSpkiHashes:      Set<String> = emptySet()
)
