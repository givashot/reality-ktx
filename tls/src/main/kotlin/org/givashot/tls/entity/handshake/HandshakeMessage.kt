package org.givashot.tls.entity.handshake

internal data class HandshakeMessage(
    val type: Int,
    val body: ByteArray,
    val encodedBytes: ByteArray,
)
