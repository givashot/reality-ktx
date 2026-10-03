package org.givashot.tls.handshake

internal data class HandshakeMessage(
    val type: Int,
    val body: ByteArray,
    val encodedBytes: ByteArray,
)
