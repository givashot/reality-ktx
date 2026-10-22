package org.givashot.tunnel.vless

/**
 * A parsed VLESS request header with all fields as sent by the client. Semantic checks such as the UUID,
 * the command, and the target are left to the caller.
 *
 * @property version the protocol version byte, echoed back in the response header.
 * @property uuid the 16-byte user ID as sent, not validated.
 * @property addons the raw addons bytes, not interpreted.
 * @property command the command byte, for example 1 for TCP.
 * @property host the target as a domain name (possibly empty) or an IP literal.
 * @property port the target port as sent, possibly 0.
 *
 * Array properties use reference equality.
 */
data class VlessRequestHeader(
    val version: Byte,
    val uuid: ByteArray,
    val addons: ByteArray,
    val command: Int,
    val host: String,
    val port: Int,
)
