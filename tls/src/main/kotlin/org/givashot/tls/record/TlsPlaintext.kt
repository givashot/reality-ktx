package org.givashot.tls.record

internal data class TlsPlaintext(
    val contentType: Int,
    val payload: ByteArray,
)
