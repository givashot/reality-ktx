package org.givashot.tls.handshake

data class HandshakeMessage(
    val type: Int,
    val body: ByteArray,
    val encodedBytes: ByteArray,
)
