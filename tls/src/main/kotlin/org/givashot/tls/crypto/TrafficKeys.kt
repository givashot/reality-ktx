package org.givashot.tls.crypto

internal class TrafficKeys(
    var key: ByteArray,
    var iv: ByteArray,
    val cipherSuite: CipherSuite,
    var sequenceNumber: Long = 0L,
    var trafficSecret: ByteArray? = null,
) {
    /** Derives the next TLS 1.3 traffic key and starts its record sequence at zero. */
    fun update() {
        val nextSecret = hkdfExpandLabel(
            checkNotNull(trafficSecret) { "Traffic secret is not available for key update" },
            "traffic upd",
            ByteArray(0),
            cipherSuite.hashLength,
            cipherSuite,
        )
        trafficSecret = nextSecret
        key = hkdfExpandLabel(nextSecret, "key", ByteArray(0), cipherSuite.keyLen, cipherSuite)
        iv = hkdfExpandLabel(nextSecret, "iv", ByteArray(0), cipherSuite.ivLen, cipherSuite)
        sequenceNumber = 0
    }
}
