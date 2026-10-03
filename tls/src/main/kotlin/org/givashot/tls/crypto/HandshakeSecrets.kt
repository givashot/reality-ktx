package org.givashot.tls.crypto

import org.givashot.tls.handshake.CipherSuite

internal data class HandshakeSecrets(
    val handshakeSecret: ByteArray,
    val serverHandshakeTrafficSecret: ByteArray,
    val clientHandshakeTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val transcriptHash: ByteArray,   // ClientHello ... ServerHello 的 hash
    val cipherSuite: CipherSuite,
    val masterSecret: ByteArray
)
