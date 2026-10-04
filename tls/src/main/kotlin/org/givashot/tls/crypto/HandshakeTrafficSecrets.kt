package org.givashot.tls.crypto

internal data class HandshakeTrafficSecrets(
    val serverHandshakeTrafficSecret: ByteArray,
    val clientHandshakeTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val cipherSuite: CipherSuite,
) {
    fun clientTrafficKeys(): TrafficKeys = TrafficKeys(clientWriteKey, clientWriteIv, cipherSuite)

    fun serverTrafficKeys(): TrafficKeys = TrafficKeys(serverWriteKey, serverWriteIv, cipherSuite)
}
