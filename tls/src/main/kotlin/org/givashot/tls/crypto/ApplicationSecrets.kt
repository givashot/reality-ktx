package org.givashot.tls.crypto

import org.givashot.tls.handshake.CipherSuite

internal data class ApplicationSecrets(
    val clientAppTrafficSecret: ByteArray,
    val serverAppTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val cipherSuite: CipherSuite
)
