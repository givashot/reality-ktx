package org.givashot.tls.entity.handshake

data class HandshakeSecrets(
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
