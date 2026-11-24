package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_KEY_SHARE_KEY
import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_SERVER_NAME_KEY
import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY
import org.givashot.tls.constant.TLS_HANDSHAKE_SERVER_NAME_HOST_NAME
import org.givashot.tls.constant.TLS_NAMED_GROUP_X25519
import org.givashot.tls.constant.TLS_VERSION_1_3

@Suppress("ArrayInDataClass")
data class ClientHello(
    val legacyVersion: Int,
    val random: ByteArray,
    val sessionId: ByteArray,
    val cipherSuites: IntArray,
    val compressionMethods: ByteArray,
    val extensions: Map<Int, ByteArray>,
    val handshakeAndBody: ByteArray,
    val sessionIdOffsetBaseHandshake: Int,
) {
    /** 从 server_name (SNI) 扩展中提取主机名 */
    val sni: String? by lazy {
        val ext = extensions[TLS_HANDSHAKE_EXTENSION_SERVER_NAME_KEY] ?: return@lazy null
        if (ext.size < 2) return@lazy null
        val listLen = readUint16(ext, 0)
        if (2 + listLen != ext.size) return@lazy null
        var offset = 2
        while (offset < ext.size) {
            if (offset + 3 > ext.size) return@lazy null
            val nameType = ext[offset].toInt() and 0xFF
            val nameLen = readUint16(ext, offset + 1)
            offset += 3
            if (offset + nameLen > ext.size) return@lazy null
            if (nameType == TLS_HANDSHAKE_SERVER_NAME_HOST_NAME) {
                return@lazy ext.decodeToString(offset, offset + nameLen)
            }
            offset += nameLen
        }
        null
    }

    /** 从 key_share 扩展中提取 32 字节 X25519 公钥 */
    val clientPubKey: ByteArray? by lazy {
        val ext = extensions[TLS_HANDSHAKE_EXTENSION_KEY_SHARE_KEY] ?: return@lazy null
        if (ext.size < 2) return@lazy null
        val sharesLen = readUint16(ext, 0)
        if (2 + sharesLen != ext.size) return@lazy null
        var offset = 2
        while (offset < ext.size) {
            if (offset + 4 > ext.size) return@lazy null
            val group = readUint16(ext, offset)
            val keyLen = readUint16(ext, offset + 2)
            offset += 4
            if (offset + keyLen > ext.size) return@lazy null
            if (group == TLS_NAMED_GROUP_X25519 && keyLen == 32) {
                return@lazy ext.copyOfRange(offset, offset + 32)
            }
            offset += keyLen
        }
        null
    }

    /** 检查 supported_versions 扩展是否包含 TLS 1.3 */
    val supportsTls13: Boolean by lazy {
        val ext = extensions[TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY] ?: return@lazy false
        if (ext.isEmpty()) return@lazy false
        val len = ext[0].toInt() and 0xFF
        if (len < 2 || len % 2 != 0 || 1 + len != ext.size) return@lazy false
        var offset = 1
        while (offset < ext.size) {
            if (readUint16(ext, offset) == TLS_VERSION_1_3) return@lazy true
            offset += 2
        }
        false
    }

    fun aadWithZeroedSessionId(): ByteArray = handshakeAndBody.copyOf().also {
        it.fill(0, sessionIdOffsetBaseHandshake, sessionIdOffsetBaseHandshake + sessionId.size)
    }

    private fun readUint16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
}
