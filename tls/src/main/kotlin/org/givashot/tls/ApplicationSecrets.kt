package org.givashot.tls

data class ApplicationSecrets(
    val clientAppTrafficSecret: ByteArray,
    val serverAppTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val cipherSuite: CipherSuite
)