package org.givashot.tls

import org.givashot.tls.entity.CipherSuite

data class ApplicationSecrets(
    val clientAppTrafficSecret: ByteArray,
    val serverAppTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val cipherSuite: CipherSuite
)