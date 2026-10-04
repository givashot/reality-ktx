package org.givashot.tls.crypto

internal data class ApplicationTrafficSecrets(
    val clientAppTrafficSecret: ByteArray,
    val serverAppTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val cipherSuite: CipherSuite,
) {
    fun clientTrafficKeys(): TrafficKeys = TrafficKeys(clientWriteKey, clientWriteIv, cipherSuite)

    fun serverTrafficKeys(): TrafficKeys = TrafficKeys(serverWriteKey, serverWriteIv, cipherSuite)
}
