package ai.snitchtt.checks

import ai.snitchtt.ThreatFlag
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal object CertCheck {
    fun findUnknownCAs(knownSpkiHashes: Set<String>): Set<ThreatFlag> {
        val flags = mutableSetOf<ThreatFlag>()
        try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as java.security.KeyStore?)
            val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
                ?: return flags
            for (cert in tm.acceptedIssuers) {
                val spki = cert.publicKey.encoded.joinToString("") { "%02x".format(it) }
                if (!knownSpkiHashes.contains(spki)) {
                    flags += ThreatFlag.UNKNOWN_CA_IN_STORE
                    break
                }
            }
        } catch (_: Exception) {}
        return flags
    }
}
