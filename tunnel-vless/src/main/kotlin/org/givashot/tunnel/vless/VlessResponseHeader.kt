package org.givashot.tunnel.vless

object VlessResponseHeader {

    /** Response header: the request version echoed back, followed by a zero-length addons field. */
    fun encode(requestVersion: Byte): ByteArray = byteArrayOf(requestVersion, 0)
}
